"""
Integration test script verifying live HTTP API endpoints of MailGuard platform.
"""

import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_endpoints():
    print("Testing GET / ...")
    r = requests.get(f"{BASE_URL}/")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert "MAILGUARD" in r.text
    print("  [OK] Home page HTML rendered successfully.")

    print("Testing GET /api/samples ...")
    r = requests.get(f"{BASE_URL}/api/samples")
    assert r.status_code == 200
    samples = r.json()["samples"]
    assert len(samples) >= 5
    print(f"  [OK] Fetched {len(samples)} sample scenarios.")

    print("Testing GET /api/samples/bec_wire_fraud ...")
    r = requests.get(f"{BASE_URL}/api/samples/bec_wire_fraud")
    assert r.status_code == 200
    sample_detail = r.json()["sample"]
    raw_email = sample_detail["raw_email"]
    print("  [OK] Sample raw email retrieved.")

    print("Testing POST /api/analyze (BEC Wire Fraud) ...")
    r = requests.post(f"{BASE_URL}/api/analyze", json={"raw_email": raw_email})
    assert r.status_code == 200
    res = r.json()
    threat = res["threat"]
    geo = res["geolocation"]
    evidence = res["evidence"]
    print(f"  [OK] Threat Score: {threat['threat_score']}/100 ({threat['threat_level']})")
    print(f"  [OK] Primary Threat: {threat['primary_threat']}")
    print(f"  [OK] Origin IP: {geo['origin_ip']} ({geo['origin_geo']['city']}, {geo['origin_geo']['country']})")
    print(f"  [OK] SHA-256 Hash: {evidence['sha256']}")
    assert geo["origin_ip"] == "102.89.23.114"
    assert "Nigeria" in geo["origin_geo"]["country"]

    print("Testing POST /api/report-forensics ...")
    r = requests.post(f"{BASE_URL}/api/report-forensics", json={
        "threat_data": threat,
        "geo_data": geo,
        "raw_content": raw_email,
        "analyst_notes": "Live API integration test dispatch.",
        "reporter_id": "Integration Test Script"
    })
    assert r.status_code == 200
    incident = r.json()["incident"]
    case_id = incident["case_id"]
    print(f"  [OK] Created Incident: {case_id}")

    print("Testing GET /api/incidents ...")
    r = requests.get(f"{BASE_URL}/api/incidents")
    assert r.status_code == 200
    incidents = r.json()["incidents"]
    assert any(inc["case_id"] == case_id for inc in incidents)
    print(f"  [OK] Case {case_id} found in active SOC Incident Docket.")

    print(f"Testing GET /api/export-stix/{case_id} ...")
    r = requests.get(f"{BASE_URL}/api/export-stix/{case_id}")
    assert r.status_code == 200
    stix_bundle = r.json()
    assert stix_bundle["type"] == "bundle"
    print("  [OK] STIX 2.1 Threat Intel Bundle exported successfully.")

    print("\nALL LIVE API ENDPOINTS VERIFIED & WORKING PERFECTLY!")

if __name__ == "__main__":
    test_endpoints()
