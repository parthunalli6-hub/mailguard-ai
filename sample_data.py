"""
MailGuard Pre-loaded Threat Samples & Scenarios
Provides real-world email threat templates for instant testing and demonstration.
"""

from typing import List, Dict, Any

SAMPLE_EMAILS: List[Dict[str, Any]] = [
    {
        "id": "bec_wire_fraud",
        "title": "🚨 CEO Wire Fraud (BEC / Spoofing)",
        "badge": "CRITICAL RISK",
        "badge_color": "#ff3366",
        "category": "Business Email Compromise",
        "description": "Executive impersonation demanding urgent $85,000 wire transfer from an originating IP in Lagos, Nigeria.",
        "raw_email": """Received: from mail-mx1.corporate-gateway.net (192.168.1.50) by mx.internal-corp.com
    with ESMTP id m91847192 for <cfo@acmeglobal.com>; Mon, 07 Sep 2026 09:14:22 +0000
Received: from out-relay.mtn-ng.com (102.89.23.114) by mail-mx1.corporate-gateway.net
    with ESMTP id q78219471; Mon, 07 Sep 2026 09:14:15 +0000
Received: from [192.168.10.4] (account-exec.mtn.net [102.89.23.114])
    by mail-client-auth.net id 827361872; Mon, 07 Sep 2026 09:13:58 +0000
X-Originating-IP: [102.89.23.114]
Authentication-Results: mx.corporate-gateway.net;
    spf=fail (sender IP 102.89.23.114 does not match acmeglobal.com);
    dkim=none;
    dmarc=fail action=quarantine
From: "Arthur Pendelton - CEO" <ceo-office-urgent@executive-board-management.xyz>
To: "Sarah Jenkins - CFO" <cfo@acmeglobal.com>
Reply-To: executive-wire-desk@protonmail.com
Subject: URGENT: Confidential Acquisition Wire Payment ($85,000.00)
Date: Mon, 07 Sep 2026 09:13:40 +0000
Message-ID: <847291048.20260907@executive-board-management.xyz>
Content-Type: text/plain; charset="UTF-8"

Sarah,

I am currently in an all-day executive board meeting regarding the confidential acquisition we discussed last month.

We need to execute an immediate earnest deposit of $85,000.00 to the escrow account today before 2:00 PM EST to secure the purchase agreement.

Please process a wire transfer immediately to the beneficiary account below:
Bank: First International Commercial Escrow
Routing Number: 021000021
Account Number: 849201948174
SWIFT: FINTUS33XXX
Beneficiary: Apex Strategic Holdings LLC

Keep this strictly private between us until the official press release tomorrow morning. Reply directly to this email once the wire confirmation receipt is generated.

Best regards,

Arthur Pendelton
Chief Executive Officer
Acme Global Industries
"""
    },
    {
        "id": "m365_credential_phish",
        "title": "🎣 Microsoft 365 Credential Harvest",
        "badge": "CRITICAL RISK",
        "badge_color": "#ff3366",
        "category": "Credential Phishing",
        "description": "Deceptive Office 365 password expiration notice routing to a Tor Exit Node IP in Moscow, Russia.",
        "raw_email": """Received: from inbound.sec-mail.com (10.0.4.12) by exchange.acmeglobal.com
    with ESMTP id e38291038; Mon, 07 Sep 2026 08:30:11 +0000
Received: from tor-exit-node-05.flokinet.is (185.220.101.5) by inbound.sec-mail.com
    with ESMTP id t9928174; Mon, 07 Sep 2026 08:29:55 +0000
X-Originating-IP: [185.220.101.5]
Authentication-Results: inbound.sec-mail.com;
    spf=softfail (mail originated from 185.220.101.5 not authorized for microsoft.com);
    dkim=fail header.d=microsoft.com;
    dmarc=fail (p=none sp=none)
From: "Microsoft Security Team" <admin-notify@microsoft-security-auth-check.xyz>
To: <target.employee@acmeglobal.com>
Subject: Action Required: Your Microsoft 365 Password Expires in 24 Hours
Date: Mon, 07 Sep 2026 08:29:40 +0000
Message-ID: <MS365-ALERT-839218@microsoft-security-auth-check.xyz>
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
<div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px; border: 1px solid #ddd;">
    <h2 style="color: #0078d4;">Microsoft Security Notification</h2>
    <p>Dear Employee,</p>
    <p>Your <strong>Microsoft 365 / Active Directory password</strong> is scheduled to expire in <strong>24 hours</strong>.</p>
    <p>To prevent immediate suspension of your OneDrive, Outlook, and Teams services, you must verify your account and keep your current password now:</p>
    <p style="text-align: center; margin: 30px 0;">
        <a href="http://185.220.101.5/office365-auth/login.php?user=target.employee" style="background: #0078d4; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold;">
            Keep Current Password & Verify Account
        </a>
    </p>
    <p style="font-size: 12px; color: #777;">If you do not complete this verification immediately, your corporate mailbox will be blocked on 08-Sep-2026.</p>
    <hr>
    <p style="font-size: 11px; color: #999;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
</div>
</body>
</html>
"""
    },
    {
        "id": "ransomware_invoice_drop",
        "title": "☣️ Weaponized Invoice Malware Drop",
        "badge": "CRITICAL RISK",
        "badge_color": "#ff3366",
        "category": "Malware / Ransomware",
        "description": "Overdue billing notice with weaponized macro-enabled container attachment routed from Panama.",
        "raw_email": """Received: from edge-filter.cloud-spam.io (172.16.8.22) by mail.acmeglobal.com
    with ESMTP id f92847291; Mon, 07 Sep 2026 07:45:00 +0000
Received: from vps-offshore-node9.panama-telecom.pa (190.14.88.42) by edge-filter.cloud-spam.io
    with ESMTP id p4910284; Mon, 07 Sep 2026 07:44:32 +0000
X-Originating-IP: [190.14.88.42]
Authentication-Results: edge-filter.cloud-spam.io;
    spf=fail;
    dkim=none;
    dmarc=fail
From: "Accounts Receivable - Swift Billing" <billing@swift-invoicing-portal.live>
To: <accounting@acmeglobal.com>
Subject: OVERDUE NOTICE: Invoice #INV-2026-9042 Overdue ($14,290.00) - Final Demand
Date: Mon, 07 Sep 2026 07:44:10 +0000
Message-ID: <INV-2026-9042@swift-invoicing-portal.live>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_98241_8472918"

------=_Part_98241_8472918
Content-Type: text/plain; charset="UTF-8"

Attention Accounts Payable,

Our records indicate that Invoice #INV-2026-9042 for the amount of $14,290.00 is now 45 days past due.

Failure to remit payment within 48 hours will result in immediate legal escalation and credit bureau reporting.

Please review the attached invoice breakdown and remittance instructions immediately:
Attachment: Invoice_INV9042_Remittance.docm

You can also download the encrypted transaction receipt here:
http://swift-invoicing-portal.live/download/receipt_secure.iso

Swift Billing Solutions Inc.
Legal & Collections Division

------=_Part_98241_8472918
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Invoice_INV9042_Remittance.docm"
Content-Disposition: attachment; filename="Invoice_INV9042_Remittance.docm"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAAAAIQAAAAAAAAAAAAAAA==
------=_Part_98241_8472918--
"""
    },
    {
        "id": "paypal_compromise_alert",
        "title": "🛑 PayPal Account Lockout Phish",
        "badge": "HIGH RISK",
        "badge_color": "#ff9900",
        "category": "Social Engineering",
        "description": "Urgent PayPal security warning hosted on a malicious Dutch bulletproof proxy with credential stealers.",
        "raw_email": """Received: from smtp-in.acmeglobal.com (192.168.0.25) by mail.acmeglobal.com
    with ESMTP id a72819472; Mon, 07 Sep 2026 06:12:30 +0000
Received: from fastflux-node.hostroyale.nl (45.154.255.89) by smtp-in.acmeglobal.com
    with ESMTP id n8291038; Mon, 07 Sep 2026 06:12:15 +0000
X-Originating-IP: [45.154.255.89]
Authentication-Results: smtp-in.acmeglobal.com;
    spf=fail (ip 45.154.255.89 is not allowed to send mail for paypal.com);
    dkim=none;
    dmarc=fail
From: "PayPal Security Alert" <service-security@paypal-verify-security.xyz>
To: <user@acmeglobal.com>
Subject: Urgent: Your PayPal account has been restricted due to unauthorized login attempt
Date: Mon, 07 Sep 2026 06:12:00 +0000
Message-ID: <PP-SECURITY-928410@paypal-verify-security.xyz>
Content-Type: text/plain; charset="UTF-8"

Dear PayPal Customer,

We detected an unauthorized login attempt to your PayPal account from an unrecognized device in Moscow, Russia on 07-Sep-2026.

As a security precaution, we have temporarily restricted access to your funds, linked cards, and transaction capabilities.

To restore full access to your account and dispute this unauthorized charge of $499.00 USD, you must verify your identity immediately:

https://paypal-verify-security.xyz/login/verify-identity.php

Failure to confirm your billing details within 12 hours will lead to permanent account suspension.

Sincerely,
PayPal Security & Fraud Prevention Center
"""
    },
    {
        "id": "clean_corporate_newsletter",
        "title": "🟢 Legitimate Corporate All-Hands Memo",
        "badge": "LOW RISK / SAFE",
        "badge_color": "#00e676",
        "category": "Legitimate",
        "description": "Internal company meeting invitation with verified SPF/DKIM cryptographic signatures from Google Workspace.",
        "raw_email": """Received: from mail-sor-f41.google.com (209.85.220.41) by mx.google.com
    with SMTPS id g18sor2918491; Mon, 07 Sep 2026 05:00:10 +0000
Received: from [10.240.0.12] (client.corp.acmeglobal.com [209.85.220.41])
    by smtp.gmail.com with ESMTPSA id q19sm9182741; Mon, 07 Sep 2026 04:59:58 +0000
X-Originating-IP: [209.85.220.41]
Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of communications@acmeglobal.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=communications@acmeglobal.com;
    dkim=pass header.i=@acmeglobal.com header.s=202601;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acmeglobal.com
From: "Acme Global Internal Communications" <communications@acmeglobal.com>
To: "All Employees" <all-staff@acmeglobal.com>
Subject: Q3 Global All-Hands Meeting & Engineering Roadmap Highlights
Date: Mon, 07 Sep 2026 04:59:45 +0000
Message-ID: <corp-memo-20260907-9481@acmeglobal.com>
Content-Type: text/plain; charset="UTF-8"

Hi Team,

Please join us this Thursday at 10:00 AM PST for our quarterly Global All-Hands meeting.

Agenda Highlights:
1. Q3 Financial Performance & Milestone Review
2. Product & AI Engineering Roadmap Updates
3. Employee Recognition & Open Q&A Session

You can add the event to your Google Calendar and view the agenda document on our internal Wiki:
https://intranet.acmeglobal.com/allhands/q3-2026

We look forward to seeing everyone there!

Warm regards,
Internal Communications & People Operations
Acme Global Industries
"""
    }
]


def get_sample_by_id(sample_id: str) -> Dict[str, Any]:
    """Returns sample email entry by its ID."""
    for s in SAMPLE_EMAILS:
        if s["id"] == sample_id:
            return s
    return SAMPLE_EMAILS[0]
