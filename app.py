"""
MailGuard AI - Email Threat Detection, Geolocation Intelligence & Forensics Platform
Main Flask Application Server
"""

import os
from flask import Flask, render_template, request, jsonify, Response, send_file
import json
from threat_engine import analyze_email_threat, parse_raw_email
from geo_engine import parse_transit_hops, query_ip_geolocation
from forensics import (
    calculate_evidence_hashes,
    create_forensic_incident,
    get_all_incidents,
    update_incident_status,
    generate_stix_bundle
)
from sample_data import SAMPLE_EMAILS, get_sample_by_id

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mailguard-threat-forensics-sec-key-2026'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload


# Pre-seed docket with a sample historical incident
initial_sample = SAMPLE_EMAILS[0]
sample_threat = analyze_email_threat(initial_sample["raw_email"])
sample_parsed = sample_threat["parsed_email"]
sample_geo = parse_transit_hops(sample_parsed["received_headers"], sample_parsed["x_originating_ip"])
create_forensic_incident(
    threat_data=sample_threat,
    geo_data=sample_geo,
    raw_content=initial_sample["raw_email"],
    analyst_notes="Historical flagged incident: Executive impersonation & wire fraud attempt originating from West African ISP subnet.",
    reporter_id="Automated SOC Sensor (Pre-loaded)"
)


@app.route("/")
def home():
    """Main CyberSOC Command Center Interface."""
    return render_template("index.html")


@app.route("/api/samples", methods=["GET"])
def get_samples():
    """Returns all preloaded sample threat scenarios."""
    # Return samples with metadata
    summary_list = []
    for s in SAMPLE_EMAILS:
        summary_list.append({
            "id": s["id"],
            "title": s["title"],
            "badge": s["badge"],
            "badge_color": s["badge_color"],
            "category": s["category"],
            "description": s["description"]
        })
    return jsonify({"status": "success", "samples": summary_list})


@app.route("/api/samples/<sample_id>", methods=["GET"])
def get_sample_detail(sample_id):
    """Returns the full raw email text for a selected sample scenario."""
    sample = get_sample_by_id(sample_id)
    return jsonify({"status": "success", "sample": sample})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyzes an email for AI threat scoring, transit hop analysis, and geolocation.
    Accepts JSON body or multipart form file upload (.eml).
    """
    raw_content = ""
    api_key = None

    if request.is_json:
        data = request.get_json() or {}
        raw_content = data.get("raw_email", "")
        api_key = data.get("api_key", None)
    elif "file" in request.files:
        file = request.files["file"]
        if file:
            raw_content = file.read().decode("utf-8", errors="replace")
    elif "email_text" in request.form:
        raw_content = request.form.get("email_text", "")

    if not raw_content or not raw_content.strip():
        return jsonify({"status": "error", "message": "No email content or file provided for analysis."}), 400

    try:
        # 1. AI Threat & Heuristic Scanning
        threat_analysis = analyze_email_threat(raw_content, custom_api_key=api_key)
        parsed_email = threat_analysis["parsed_email"]

        # 2. Origin Geolocation & SMTP Transit Hop Tracing
        geo_analysis = parse_transit_hops(
            received_headers=parsed_email.get("received_headers", []),
            explicit_origin_ip=parsed_email.get("x_originating_ip", "")
        )

        # 3. Cryptographic Evidence Hashes
        evidence_hashes = calculate_evidence_hashes(raw_content)

        return jsonify({
            "status": "success",
            "threat": threat_analysis,
            "geolocation": geo_analysis,
            "evidence": evidence_hashes,
            "raw_preview": raw_content[:1500]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/report-forensics", methods=["POST"])
def report_forensics():
    """Dispatches analysis findings to the SOC Forensics Incident Docket."""
    data = request.get_json() or {}
    threat_data = data.get("threat_data")
    geo_data = data.get("geo_data")
    raw_content = data.get("raw_content", "")
    analyst_notes = data.get("analyst_notes", "")
    reporter_id = data.get("reporter_id", "SOC Tier-1 Analyst")

    if not threat_data or not geo_data:
        return jsonify({"status": "error", "message": "Incomplete threat or geolocation data."}), 400

    incident = create_forensic_incident(
        threat_data=threat_data,
        geo_data=geo_data,
        raw_content=raw_content,
        analyst_notes=analyst_notes,
        reporter_id=reporter_id
    )

    return jsonify({
        "status": "success",
        "message": f"Incident successfully filed under {incident['case_id']}",
        "incident": incident
    })


@app.route("/api/incidents", methods=["GET"])
def list_incidents():
    """Returns all forensic incident cases in the docket."""
    incidents = get_all_incidents()
    return jsonify({"status": "success", "count": len(incidents), "incidents": incidents})


@app.route("/api/incidents/<case_id>/status", methods=["POST"])
def update_status(case_id):
    """Updates the status of a specific forensic incident."""
    data = request.get_json() or {}
    new_status = data.get("status", "INVESTIGATING")
    updated = update_incident_status(case_id, new_status)
    if updated:
        return jsonify({"status": "success", "incident": updated})
    return jsonify({"status": "error", "message": "Incident not found"}), 404


@app.route("/api/export-stix/<case_id>", methods=["GET"])
def export_stix(case_id):
    """Exports a STIX 2.1 JSON bundle for a specific case."""
    bundle = generate_stix_bundle(case_id)
    if "error" in bundle:
        return jsonify({"status": "error", "message": bundle["error"]}), 404

    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=stix_{case_id}.json"}
    )


@app.route("/api/lookup-ip/<ip>", methods=["GET"])
def lookup_single_ip(ip):
    """Direct IP Geolocation lookup endpoint."""
    geo = query_ip_geolocation(ip)
    return jsonify({"status": "success", "geo": geo})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)