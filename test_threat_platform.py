"""
Automated unit and integration tests for MailGuard backend platform.
"""

import unittest
from threat_engine import analyze_email_threat, parse_raw_email, defang_url
from geo_engine import parse_transit_hops, query_ip_geolocation
from forensics import (
    calculate_evidence_hashes,
    create_forensic_incident,
    generate_stix_bundle,
    get_all_incidents
)
from sample_data import SAMPLE_EMAILS


class TestMailGuard(unittest.TestCase):

    def test_bec_threat_scoring(self):
        bec_sample = SAMPLE_EMAILS[0]
        result = analyze_email_threat(bec_sample["raw_email"])
        self.assertGreaterEqual(result["threat_score"], 60)
        self.assertIn("CRITICAL", result["threat_level"])
        self.assertTrue(any("T1534" in m["id"] or "T1566" in m["id"] for m in result["mitre_attack"]))
        self.assertTrue(len(result["iocs"]) > 0)

    def test_clean_memo_scoring(self):
        clean_sample = SAMPLE_EMAILS[4]
        result = analyze_email_threat(clean_sample["raw_email"])
        self.assertLess(result["threat_score"], 30)
        self.assertEqual(result["verdict"], "BENIGN")

    def test_geolocation_transit_hops(self):
        bec_sample = SAMPLE_EMAILS[0]
        parsed = parse_raw_email(bec_sample["raw_email"])
        hops_data = parse_transit_hops(parsed["received_headers"], parsed["x_originating_ip"])
        self.assertEqual(hops_data["origin_ip"], "102.89.23.114")
        self.assertEqual(hops_data["origin_geo"]["country"], "Nigeria")
        self.assertEqual(hops_data["origin_geo"]["city"], "Lagos")
        self.assertGreaterEqual(hops_data["hop_count"], 2)

    def test_russia_tor_hop(self):
        m365_sample = SAMPLE_EMAILS[1]
        parsed = parse_raw_email(m365_sample["raw_email"])
        hops_data = parse_transit_hops(parsed["received_headers"], parsed["x_originating_ip"])
        self.assertEqual(hops_data["origin_ip"], "185.220.101.5")
        self.assertEqual(hops_data["origin_geo"]["country"], "Russia")

    def test_evidence_hashing_and_forensics(self):
        sample = SAMPLE_EMAILS[1]
        threat = analyze_email_threat(sample["raw_email"])
        geo = parse_transit_hops(threat["parsed_email"]["received_headers"])
        hashes = calculate_evidence_hashes(sample["raw_email"])
        self.assertEqual(len(hashes["sha256"]), 64)
        self.assertEqual(len(hashes["md5"]), 32)

        incident = create_forensic_incident(
            threat_data=threat,
            geo_data=geo,
            raw_content=sample["raw_email"],
            analyst_notes="Test incident report"
        )
        self.assertTrue(incident["case_id"].startswith("CASE-2026-"))
        self.assertEqual(incident["status"], "INVESTIGATING")

        # Test STIX Bundle generation
        stix = generate_stix_bundle(incident["case_id"])
        self.assertEqual(stix["type"], "bundle")
        self.assertEqual(len(stix["objects"]), 3)


if __name__ == "__main__":
    unittest.main()
