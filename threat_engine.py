"""
MailGuard AI Threat Detection & Heuristics Analysis Engine
Analyzes raw email content, SPF/DKIM/DMARC headers, sender authenticity,
suspicious URLs, weaponized attachments, NLP coercion indicators, and computes threat scores.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

# High-risk TLDs often leveraged in throwaway phishing campaigns
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.ru', '.click', '.live', '.loan', '.work', '.zip',
    '.gq', '.tk', '.ml', '.ga', '.cf', '.buzz', '.rest', '.monster', '.icu', '.cam'
}

# High-risk file extensions
HIGH_RISK_ATTACHMENT_EXTS = {
    '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta', '.wsf',
    '.iso', '.img', '.docm', '.xlsm', '.pptm', '.jar', '.dll', '.cpl'
}

# Suspicious keywords for Phishing & Credential Harvest
CRED_KEYWORDS = [
    'password expired', 'reset your password', 'verify your account',
    'suspended account', 'unauthorized access', 'login attempt',
    'confirm identity', 'security update', 'session timeout', 'billing failure',
    'update payment', 'action required immediately', 'microsoft 365', 'office 365',
    'onedrive share', 'docusign document', 'review invoice'
]

# Suspicious keywords for BEC / Wire Transfer Fraud
BEC_KEYWORDS = [
    'wire transfer', 'urgent transfer', 'payment pending', 'fund transfer',
    'confidential inquiry', 'strictly private', 'swift code', 'routing number',
    'beneficiary account', 'executive request', 'ceo request', 'acquisition deposit',
    'process immediately', 'keep this between us', 'are you at your desk'
]

# Suspicious keywords for Extortion / Ransomware
RANSOM_KEYWORDS = [
    'bitcoin', 'btc wallet', 'encrypted files', 'decryptor tool', 'hacked your webcam',
    'recorded video', 'compromised system', 'pay the ransom', 'private key'
]


def defang_url(url: str) -> str:
    """Defangs a URL so it cannot be clicked accidentally (e.g., hxxps[:]//...)."""
    return url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')


def defang_ip(ip: str) -> str:
    """Defangs an IP address (e.g., 192[.]168[.]1[.]1)."""
    return ip.replace('.', '[.]')


def parse_raw_email(raw_text: str) -> Dict[str, Any]:
    """
    Parses raw email string (either RFC 822 format with headers, or pasted text).
    Extracts headers, body text, URLs, and attachments.
    """
    parsed_msg = None
    headers: Dict[str, Any] = {}
    body_text = ""
    received_headers = []
    attachments = []

    try:
        # Try standard RFC parser first
        if "From:" in raw_text or "Subject:" in raw_text or "Received:" in raw_text:
            parsed_msg = Parser(policy=policy.default).parsestr(raw_text)
            for k, v in parsed_msg.items():
                if k.lower() == "received":
                    received_headers.append(str(v))
                else:
                    headers[k] = str(v)
            
            # Extract body
            if parsed_msg.is_multipart():
                for part in parsed_msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disposition:
                        fname = part.get_filename() or "unnamed_attachment"
                        attachments.append({
                            "filename": fname,
                            "content_type": content_type,
                            "size_bytes": len(part.get_payload(decode=True) or b"")
                        })
                    elif content_type in ["text/plain", "text/html"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body_text += "\n" + payload.decode(errors="replace")
                        except Exception:
                            body_text += "\n" + str(part.get_payload() or "")
            else:
                body_text = parsed_msg.get_body(preferencelist=('plain', 'html'))
                body_text = body_text.get_content() if body_text else str(parsed_msg.get_payload() or "")
    except Exception:
        pass

    # Fallback regex extraction if standard parser returned minimal headers
    if not headers.get("From") and not headers.get("Subject"):
        from_match = re.search(r'(?i)^From:\s*(.+)$', raw_text, re.MULTILINE)
        to_match = re.search(r'(?i)^To:\s*(.+)$', raw_text, re.MULTILINE)
        sub_match = re.search(r'(?i)^Subject:\s*(.+)$', raw_text, re.MULTILINE)
        date_match = re.search(r'(?i)^Date:\s*(.+)$', raw_text, re.MULTILINE)
        reply_match = re.search(r'(?i)^Reply-To:\s*(.+)$', raw_text, re.MULTILINE)
        auth_match = re.search(r'(?i)^Authentication-Results:\s*(.+)$', raw_text, re.MULTILINE)
        x_orig_match = re.search(r'(?i)^X-Originating-IP:\s*\[?([0-9\.]+)\]?', raw_text, re.MULTILINE)

        if from_match: headers["From"] = from_match.group(1).strip()
        if to_match: headers["To"] = to_match.group(1).strip()
        if sub_match: headers["Subject"] = sub_match.group(1).strip()
        if date_match: headers["Date"] = date_match.group(1).strip()
        if reply_match: headers["Reply-To"] = reply_match.group(1).strip()
        if auth_match: headers["Authentication-Results"] = auth_match.group(1).strip()
        if x_orig_match: headers["X-Originating-IP"] = x_orig_match.group(1).strip()

        # Extract all Received headers via regex
        rec_matches = re.findall(r'(?is)Received:\s*([^;]+;[^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)', raw_text)
        if rec_matches:
            received_headers = [m.strip() for m in rec_matches]

        if not body_text:
            body_text = raw_text

    # Extract clean From Name & Address
    from_header = headers.get("From", "Unknown Sender")
    sender_name = from_header
    sender_email = ""
    email_regex_match = re.search(r'<([^>]+)>|([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', from_header)
    if email_regex_match:
        sender_email = (email_regex_match.group(1) or email_regex_match.group(2)).strip().lower()
        sender_name = re.sub(r'<[^>]+>', '', from_header).strip().strip('"\'')
        if not sender_name:
            sender_name = sender_email

    # Extract all URLs in body
    urls_found = re.findall(r'https?://[^\s<>"\'{}|\\^`]+', body_text)
    # Deduplicate while preserving order
    seen_urls = set()
    clean_urls = []
    for u in urls_found:
        u_clean = u.rstrip('.,;:)')
        if u_clean not in seen_urls:
            seen_urls.add(u_clean)
            clean_urls.append(u_clean)

    # Detect attachments mentioned in headers or text
    if not attachments:
        attach_matches = re.findall(r'(?i)filename=[\'"]?([^\'";\r\n]+)[\'"]?', raw_text)
        for att in attach_matches:
            attachments.append({
                "filename": att.strip(),
                "content_type": "application/octet-stream",
                "size_bytes": 0
            })

    return {
        "headers": headers,
        "received_headers": received_headers,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "sender_domain": sender_email.split('@')[-1] if '@' in sender_email else "",
        "subject": headers.get("Subject", "No Subject"),
        "date": headers.get("Date", "Unknown Date"),
        "to": headers.get("To", "Undisclosed Recipients"),
        "reply_to": headers.get("Reply-To", ""),
        "auth_results": headers.get("Authentication-Results", ""),
        "x_originating_ip": headers.get("X-Originating-IP", ""),
        "body": body_text.strip(),
        "urls": clean_urls,
        "attachments": attachments
    }


def analyze_email_threat(raw_content: str, custom_api_key: str = None) -> Dict[str, Any]:
    """
    Main AI & Forensic analysis function.
    Evaluates spoofing, headers, URLs, attachments, NLP sentiment, and produces a Threat Score & IOC list.
    """
    parsed = parse_raw_email(raw_content)
    body_lower = parsed["body"].lower()
    subject_lower = parsed["subject"].lower()
    combined_text = f"{subject_lower}\n{body_lower}"

    risk_factors = []
    mitre_attack = []
    iocs = []
    threat_types = []
    score = 5  # Baseline score

    # 1. Header & Domain Authenticity Scanner (SPF / DKIM / DMARC / Spoofing)
    auth_res = parsed["auth_results"].lower()
    from_dom = parsed["sender_domain"].lower()
    reply_to = parsed["reply_to"].lower()

    # Check SPF/DKIM flags in headers
    spf_fail = "spf=fail" in auth_res or "spf=softfail" in auth_res
    dkim_fail = "dkim=fail" in auth_res
    dmarc_fail = "dmarc=fail" in auth_res

    if spf_fail or dkim_fail or dmarc_fail:
        score += 25
        risk_factors.append({
            "category": "Authentication Failure",
            "title": "SPF / DKIM / DMARC Verification Failed",
            "severity": "CRITICAL",
            "description": f"Email headers failed cryptographic domain validation ({'SPF Fail ' if spf_fail else ''}{'DKIM Fail ' if dkim_fail else ''}{'DMARC Fail' if dmarc_fail else ''}). High indicator of sender forging."
        })
        mitre_attack.append({
            "id": "T1566.002",
            "tactic": "Initial Access",
            "technique": "Phishing: Email Spoofing & Header Manipulation"
        })

    # Display name spoofing (e.g. "Microsoft Team <admin@temp-domain.xyz>")
    suspicious_impersonation_names = [
        "microsoft", "office 365", "paypal", "google security", "apple support",
        "it helpdesk", "ceo", "cfo", "human resources", "admin", "billing department",
        "docusign", "dropbox", "payroll"
    ]
    impersonated = None
    for brand in suspicious_impersonation_names:
        if brand in parsed["sender_name"].lower() and brand not in from_dom:
            impersonated = brand
            break

    if impersonated:
        score += 30
        threat_types.append("Display Name Impersonation / Spoofing")
        risk_factors.append({
            "category": "Sender Impersonation",
            "title": f"Display Name Forgery ({impersonated.title()})",
            "severity": "CRITICAL",
            "description": f"Sender display name claims to be '{parsed['sender_name']}' but originates from untrusted domain '@{from_dom}'."
        })
        mitre_attack.append({
            "id": "T1566",
            "tactic": "Initial Access",
            "technique": "Phishing: Display Name Impersonation"
        })

    # Reply-To mismatch
    if reply_to and from_dom and '@' in reply_to:
        reply_dom = reply_to.split('@')[-1].lower().strip('>')
        if reply_dom != from_dom and not (reply_dom in from_dom or from_dom in reply_dom):
            score += 20
            risk_factors.append({
                "category": "Header Discrepancy",
                "title": "Reply-To Header Domain Mismatch",
                "severity": "HIGH",
                "description": f"Replies will be silently redirected to '@{reply_dom}' instead of the sender domain '@{from_dom}'."
            })

    # 2. URL & Link Reputation Scanner
    flagged_urls = []
    for u in parsed["urls"]:
        try:
            parsed_u = urlparse(u)
            domain = parsed_u.netloc.lower()
            path = parsed_u.path.lower()
            tld = '.' + domain.split('.')[-1] if '.' in domain else ''

            is_url_suspicious = False
            url_reasons = []

            # Check TLD
            if tld in SUSPICIOUS_TLDS:
                is_url_suspicious = True
                url_reasons.append(f"Suspicious top-level domain ({tld})")

            # Check if raw IP is used in URL
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$', domain):
                is_url_suspicious = True
                url_reasons.append("Direct IP address used instead of hostname")

            # Check lookalike brand in subdomain or path
            for brand in ['microsoft', 'paypal', 'apple', 'google', 'netflix', 'amazon', 'chase', 'bank']:
                if brand in domain and not domain.endswith(f".{brand}.com") and domain != f"{brand}.com":
                    is_url_suspicious = True
                    url_reasons.append(f"Typosquatted / lookalike brand name ({brand})")

            # Check credential phishing keywords in URL
            if any(k in path for k in ['login', 'signin', 'auth', 'verify', 'update', 'password', 'secure', 'wallet']):
                url_reasons.append("Credential harvesting endpoint pattern")
                if is_url_suspicious:
                    threat_types.append("Credential Phishing Link")

            if is_url_suspicious or len(url_reasons) > 0:
                score += 20
                defanged = defang_url(u)
                flagged_urls.append({
                    "raw_url": u,
                    "defanged_url": defanged,
                    "domain": domain,
                    "reasons": url_reasons
                })
                iocs.append({
                    "type": "Malicious / Suspicious URL",
                    "value": defanged,
                    "context": ", ".join(url_reasons)
                })
        except Exception:
            pass

    if flagged_urls:
        risk_factors.append({
            "category": "Weaponized Links",
            "title": f"Detected {len(flagged_urls)} Suspicious / Phishing URL(s)",
            "severity": "CRITICAL" if score > 50 else "HIGH",
            "description": f"URLs contain suspicious TLDs, raw IPs, or lookalike domain patterns: {flagged_urls[0]['defanged_url']}"
        })
        mitre_attack.append({
            "id": "T1566.002",
            "tactic": "Initial Access",
            "technique": "Phishing: Spearphishing Link"
        })

    # 3. Attachment Scanner
    flagged_attachments = []
    for att in parsed["attachments"]:
        fname = att["filename"].lower()
        ext = '.' + fname.split('.')[-1] if '.' in fname else ''
        if ext in HIGH_RISK_ATTACHMENT_EXTS or '.exe.' in fname or '.zip' in fname or '.iso' in fname:
            score += 35
            threat_types.append("Malware / Exploit Payload Delivery")
            flagged_attachments.append(att)
            iocs.append({
                "type": "Suspicious Attachment File",
                "value": att["filename"],
                "context": f"High-risk extension ({ext}) or container"
            })
            risk_factors.append({
                "category": "Weaponized Attachment",
                "title": f"High-Risk File Attached ({att['filename']})",
                "severity": "CRITICAL",
                "description": f"Attachment has high-risk extension '{ext}' commonly weaponized for ransomware, trojans, or infostealers."
            })
            mitre_attack.append({
                "id": "T1566.001",
                "tactic": "Initial Access",
                "technique": "Phishing: Spearphishing Attachment"
            })

    # 4. NLP Heuristics: Urgency, Coercion, BEC, Ransomware
    urgency_hits = [k for k in CRED_KEYWORDS if k in combined_text]
    bec_hits = [k for k in BEC_KEYWORDS if k in combined_text]
    ransom_hits = [k for k in RANSOM_KEYWORDS if k in combined_text]

    if bec_hits:
        score += 25
        threat_types.append("Business Email Compromise (BEC) / Wire Fraud")
        risk_factors.append({
            "category": "Social Engineering",
            "title": "Executive Financial Coercion / BEC Patterns",
            "severity": "HIGH",
            "description": f"Detected financial transfer / executive authority keywords: {', '.join(bec_hits[:3])}."
        })
        mitre_attack.append({
            "id": "T1534",
            "tactic": "Lateral Movement / Initial Access",
            "technique": "Internal Spearphishing & Financial Fraud"
        })

    if urgency_hits and not bec_hits:
        score += 15
        threat_types.append("Credential Harvesting & Account Phishing")
        risk_factors.append({
            "category": "Psychological Manipulation",
            "title": "Artificial Urgency & Credential Harvesting Intent",
            "severity": "MEDIUM",
            "description": f"Language uses coercive urgency to bypass user scrutiny: {', '.join(urgency_hits[:3])}."
        })
        mitre_attack.append({
            "id": "T1078",
            "tactic": "Defense Evasion",
            "technique": "Valid Accounts: Credential Harvesting"
        })

    if ransom_hits:
        score += 35
        threat_types.append("Extortion / Ransomware Demand")
        risk_factors.append({
            "category": "Extortion / Threat",
            "title": "Cryptocurrency Extortion / Blackmail Signatures",
            "severity": "CRITICAL",
            "description": f"Detected extortion demands: {', '.join(ransom_hits[:3])}."
        })

    # Check for IoC sender
    if parsed["sender_email"]:
        iocs.append({
            "type": "Sender Identity",
            "value": parsed["sender_email"],
            "context": f"From Domain: {parsed['sender_domain'] or 'N/A'}"
        })

    # Normalize Score between 0 and 100
    final_score = min(max(score, 0), 100)

    # Determine Threat Tier
    if final_score >= 75:
        threat_level = "CRITICAL RISK"
        threat_color = "#ff3366"  # Cyber Red
        verdict = "MALICIOUS"
        primary_threat = threat_types[0] if threat_types else "High-Risk Malicious Phishing Campaign"
    elif final_score >= 50:
        threat_level = "HIGH RISK"
        threat_color = "#ff9900"  # Amber Orange
        verdict = "SUSPICIOUS"
        primary_threat = threat_types[0] if threat_types else "Suspicious Social Engineering / Phishing"
    elif final_score >= 25:
        threat_level = "MEDIUM RISK"
        threat_color = "#ffcc00"  # Yellow
        verdict = "ANOMALOUS"
        primary_threat = "Potential Spam / Low-Risk Heuristic Anomaly"
    else:
        threat_level = "LOW RISK"
        threat_color = "#00e676"  # Cyber Green
        verdict = "BENIGN"
        primary_threat = "Legitimate / Clean Corporate Communication"

    # AI Summary & SOC Analyst Remediation Recommendations
    recommendations = []
    if final_score >= 50:
        recommendations.append("Isolate recipient endpoint and check proxy/DNS logs for outbound connections.")
        recommendations.append("Block originating sender address and sender IP across mail gateways.")
        if flagged_urls:
            recommendations.append(f"Add flagged domain(s) ({flagged_urls[0]['domain']}) to enterprise firewall / EDR blocklist.")
        if impersonated:
            recommendations.append("Issue executive impersonation advisory to target department / VIP users.")
        recommendations.append("Rotate credentials immediately if recipient clicked any links or submitted forms.")
    else:
        recommendations.append("No immediate containment required. Monitor for anomalous pattern repetitions.")
        recommendations.append("Ensure DMARC reject enforcement is maintained across inbound gateways.")

    # Deduplicate MITRE entries
    unique_mitre = []
    seen_ids = set()
    for m in mitre_attack:
        if m["id"] not in seen_ids:
            seen_ids.add(m["id"])
            unique_mitre.append(m)

    return {
        "parsed_email": parsed,
        "threat_score": final_score,
        "threat_level": threat_level,
        "threat_color": threat_color,
        "verdict": verdict,
        "primary_threat": primary_threat,
        "threat_types": list(set(threat_types)),
        "risk_factors": risk_factors,
        "flagged_urls": flagged_urls,
        "flagged_attachments": flagged_attachments,
        "mitre_attack": unique_mitre,
        "iocs": iocs,
        "recommendations": recommendations,
        "analysis_timestamp": parsed["date"]
    }
