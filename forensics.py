"""
MailGuard Forensics & Incident Response Module
Generates cryptographic evidence hashes, maintains the SOC Forensics Incident Docket,
and exports STIX 2.1 Threat Intelligence bundles.
"""

import hashlib
import uuid
import datetime
from typing import Dict, Any, List, Optional

# In-memory Incident Queue for the SOC Forensics Docket
FORENSIC_INCIDENTS: List[Dict[str, Any]] = []


def calculate_evidence_hashes(raw_content: str) -> Dict[str, str]:
    """Computes SHA-256 and MD5 cryptographic hashes for chain of custody."""
    content_bytes = raw_content.encode('utf-8', errors='replace')
    return {
        "sha256": hashlib.sha256(content_bytes).hexdigest(),
        "md5": hashlib.md5(content_bytes).hexdigest(),
        "byte_size": len(content_bytes)
    }


def create_forensic_incident(
    threat_data: Dict[str, Any],
    geo_data: Dict[str, Any],
    raw_content: str,
    analyst_notes: str = "",
    reporter_id: str = "Automated AI Sensor / SOC Agent"
) -> Dict[str, Any]:
    """
    Creates a formal forensic incident case in the SOC docket.
    """
    hashes = calculate_evidence_hashes(raw_content)
    incident_num = str(uuid.uuid4().hex[:6]).upper()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    case_id = f"CASE-2026-{incident_num}"

    # Determine priority based on threat score
    score = threat_data.get("threat_score", 0)
    if score >= 75:
        priority = "P1 - CRITICAL"
    elif score >= 50:
        priority = "P2 - HIGH"
    elif score >= 25:
        priority = "P3 - MEDIUM"
    else:
        priority = "P4 - INFORMATIONAL"

    incident = {
        "case_id": case_id,
        "created_at": now_str,
        "status": "INVESTIGATING",
        "priority": priority,
        "reporter": reporter_id,
        "assigned_team": "Cyber Forensics & Incident Response (DFIR Tier-2)",
        "subject": threat_data["parsed_email"].get("subject", "N/A"),
        "sender": threat_data["parsed_email"].get("sender_email", "N/A"),
        "origin_ip": geo_data.get("origin_ip", "Unknown"),
        "origin_country": geo_data.get("origin_geo", {}).get("country", "Unknown"),
        "origin_city": geo_data.get("origin_geo", {}).get("city", "Unknown"),
        "threat_score": score,
        "threat_level": threat_data.get("threat_level", "UNKNOWN"),
        "verdict": threat_data.get("verdict", "UNKNOWN"),
        "primary_threat": threat_data.get("primary_threat", "N/A"),
        "evidence_hashes": hashes,
        "analyst_notes": analyst_notes or f"Automated detection flagged {threat_data.get('primary_threat', 'threat')} with Threat Score {score}/100.",
        "iocs": threat_data.get("iocs", []),
        "mitre_attack": threat_data.get("mitre_attack", []),
        "hop_count": geo_data.get("hop_count", 0),
        "hops": geo_data.get("hops", []),
        "raw_snippet": raw_content[:500] + ("..." if len(raw_content) > 500 else "")
    }

    # Add to in-memory docket (newest first)
    FORENSIC_INCIDENTS.insert(0, incident)
    return incident


def get_all_incidents() -> List[Dict[str, Any]]:
    """Returns all forensic cases in the SOC docket."""
    return FORENSIC_INCIDENTS


def update_incident_status(case_id: str, new_status: str) -> Optional[Dict[str, Any]]:
    """Updates the lifecycle status of a forensic incident."""
    for inc in FORENSIC_INCIDENTS:
        if inc["case_id"] == case_id:
            inc["status"] = new_status
            return inc
    return None


def generate_stix_bundle(case_id: str) -> Dict[str, Any]:
    """
    Generates an industry-standard STIX 2.1 Threat Intelligence Bundle
    compatible with SIEM / SOAR tools (Splunk, Microsoft Sentinel, Cortex XSOAR).
    """
    target_inc = None
    for inc in FORENSIC_INCIDENTS:
        if inc["case_id"] == case_id:
            target_inc = inc
            break

    if not target_inc:
        return {"error": "Incident not found"}

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    bundle_id = f"bundle--{uuid.uuid4()}"
    report_id = f"report--{uuid.uuid4()}"
    indicator_id = f"indicator--{uuid.uuid4()}"
    observed_id = f"observed-data--{uuid.uuid4()}"

    objects = [
        {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Digital Forensics Threat Dossier: {target_inc['case_id']}",
            "description": f"AI Forensics Intelligence for email threat '{target_inc['subject']}'. Primary threat: {target_inc['primary_threat']}.",
            "published": now_iso,
            "report_types": ["threat-actor", "indicator", "malicious-activity"],
            "object_refs": [indicator_id, observed_id]
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Origin Malicious IP: {target_inc['origin_ip']}",
            "description": f"Originating IP for {target_inc['primary_threat']} located in {target_inc['origin_city']}, {target_inc['origin_country']}.",
            "pattern": f"[ipv4-addr:value = '{target_inc['origin_ip']}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": int(target_inc["threat_score"])
        },
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now_iso,
            "modified": now_iso,
            "first_observed": now_iso,
            "last_observed": now_iso,
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "email-message",
                    "subject": target_inc["subject"],
                    "from_ref": "1",
                    "received_lines": [h.get("header_snippet", "") for h in target_inc.get("hops", [])]
                },
                "1": {
                    "type": "email-addr",
                    "value": target_inc["sender"]
                }
            }
        }
    ]

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
