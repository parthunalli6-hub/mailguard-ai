/**
 * MailGuard AI - CyberSOC Threat Detection, Hop Geolocation & Forensics Script
 */

let currentAnalysisData = null;
let currentRawContent = "";
let currentSampleId = "bec_wire_fraud";
let threatMap = null;
let mapMarkers = [];
let mapPolyline = null;
let activeCaseId = "DRAFT";

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    initLeafletMap();
    loadSample("bec_wire_fraud");
    fetchIncidentsCount();
});

/* ==========================================================================
   Leaflet Map Initialization
   ========================================================================== */
function initLeafletMap() {
    const mapElement = document.getElementById("threatMap");
    if (!mapElement) return;

    // Default center (Atlantic view)
    threatMap = L.map('threatMap', {
        zoomControl: true,
        attributionControl: false
    }).setView([25, 0], 2);

    // High performance dark tiles (CartoDB Dark Matter)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        subdomains: 'abcd',
    }).addTo(threatMap);
}

function updateMapHops(hops, originGeo) {
    if (!threatMap) return;

    // Clear existing markers and lines
    mapMarkers.forEach(m => threatMap.removeLayer(m));
    mapMarkers = [];
    if (mapPolyline) {
        threatMap.removeLayer(mapPolyline);
        mapPolyline = null;
    }

    const latLngs = [];

    // Filter valid coordinates
    hops.forEach((hop, idx) => {
        const geo = hop.geo;
        if (geo && typeof geo.lat === 'number' && typeof geo.lon === 'number' && (geo.lat !== 0 || geo.lon !== 0)) {
            const isOrigin = (idx === 0 || hop.ip === originGeo.ip);
            const latLng = [geo.lat, geo.lon];
            latLngs.push(latLng);

            // Custom Pulsing Marker Icon
            const markerHtml = isOrigin ?
                `<div style="
                    background: #ff3366;
                    width: 18px;
                    height: 18px;
                    border-radius: 50%;
                    border: 2px solid #ffffff;
                    box-shadow: 0 0 16px #ff3366, 0 0 30px #ff3366;
                    animation: pulseGlow 1.5s infinite;
                "></div>` :
                `<div style="
                    background: #00f0ff;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    border: 2px solid #060911;
                    box-shadow: 0 0 10px #00f0ff;
                "></div>`;

            const customIcon = L.divIcon({
                html: markerHtml,
                className: 'custom-leaflet-marker',
                iconSize: [20, 20],
                iconAnchor: [10, 10]
            });

            const popupContent = `
                <div style="font-family: 'Outfit', sans-serif; font-size: 12px; color: #111827; min-width: 180px;">
                    <strong style="color: ${isOrigin ? '#ff3366' : '#0284c7'}; font-size: 13px;">
                        ${isOrigin ? '🚨 ORIGIN HOST' : '🔄 ' + hop.role}
                    </strong><br>
                    <strong>IP:</strong> <code style="background: #f1f5f9; padding: 1px 4px; border-radius: 3px;">${hop.ip}</code><br>
                    <strong>Location:</strong> ${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}<br>
                    <strong>ISP / Org:</strong> ${geo.isp || geo.org || 'N/A'}<br>
                    <strong>ASN:</strong> ${geo.asn || 'N/A'}
                </div>
            `;

            const marker = L.marker(latLng, { icon: customIcon }).addTo(threatMap);
            marker.bindPopup(popupContent);
            mapMarkers.push(marker);
        }
    });

    // Draw route polyline if at least 2 points exist
    if (latLngs.length > 1) {
        mapPolyline = L.polyline(latLngs, {
            color: '#00f0ff',
            weight: 3,
            opacity: 0.8,
            dashArray: '8, 8',
            lineCap: 'round'
        }).addTo(threatMap);
    }

    // Auto fit map view to show all hops with padding
    if (latLngs.length > 0) {
        threatMap.fitBounds(latLngs, { padding: [40, 40], maxZoom: 6 });
    }
}

/* ==========================================================================
   Sample Scenario Loader
   ========================================================================== */
async function loadSample(sampleId) {
    currentSampleId = sampleId;

    // Update active pill UI
    document.querySelectorAll(".sample-pill").forEach(p => p.classList.remove("active"));
    const activeBtn = Array.from(document.querySelectorAll(".sample-pill")).find(b => b.getAttribute("onclick")?.includes(sampleId));
    if (activeBtn) activeBtn.classList.add("active");

    try {
        const res = await fetch(`/api/samples/${sampleId}`);
        const data = await res.json();
        if (data.status === "success" && data.sample) {
            document.getElementById("emailTextInput").value = data.sample.raw_email;
            switchInputMode('paste');
            // Auto run analysis on sample switch
            runAnalysis();
        }
    } catch (err) {
        console.error("Failed to load sample:", err);
    }
}

/* ==========================================================================
   Input Controls (Paste vs Upload)
   ========================================================================== */
function switchInputMode(mode) {
    const pasteArea = document.getElementById("pasteInputArea");
    const uploadArea = document.getElementById("uploadInputArea");
    const pasteBtn = document.getElementById("modePasteBtn");
    const uploadBtn = document.getElementById("modeUploadBtn");

    if (mode === "paste") {
        pasteArea.classList.add("active");
        uploadArea.classList.remove("active");
        pasteBtn.classList.add("active");
        uploadBtn.classList.remove("active");
    } else {
        pasteArea.classList.remove("active");
        uploadArea.classList.add("active");
        pasteBtn.classList.remove("active");
        uploadBtn.classList.add("active");
    }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        document.getElementById("fileNameDisplay").textContent = `Selected: ${file.name} (${Math.round(file.size / 1024)} KB)`;
        const reader = new FileReader();
        reader.onload = (e) => {
            document.getElementById("emailTextInput").value = e.target.result;
            showToast(`Loaded EML file: ${file.name}`);
            runAnalysis();
        };
        reader.readAsText(file);
    }
}

function clearInput() {
    document.getElementById("emailTextInput").value = "";
    document.getElementById("fileNameDisplay").textContent = "No file chosen";
    document.getElementById("headerSummaryCard").style.display = "none";
    showToast("Cleared email ingestion sensor.");
}

/* ==========================================================================
   Analysis Execution & Multi-stage Scanning Simulation
   ========================================================================== */
async function runAnalysis() {
    const emailContent = document.getElementById("emailTextInput").value.trim();
    if (!emailContent) {
        showToast("Please enter or upload an email to scan.");
        return;
    }

    currentRawContent = emailContent;

    // UI Loading state
    const analyzeBtn = document.getElementById("analyzeBtn");
    const btnContent = analyzeBtn.querySelector(".btn-content");
    const btnSpinner = analyzeBtn.querySelector(".btn-spinner");
    const scanBox = document.getElementById("scanProgressBox");
    const scanBar = document.getElementById("scanProgressBar");
    const scanStep = document.getElementById("scanStepText");

    btnContent.style.display = "none";
    btnSpinner.style.display = "block";
    analyzeBtn.disabled = true;
    scanBox.style.display = "block";
    scanBar.style.width = "10%";
    scanStep.innerHTML = `<i class="fa-solid fa-radar"></i> Step 1/4: Parsing MIME headers & SPF/DKIM authentication...`;

    try {
        // Multi-stage scan UI progression
        await new Promise(r => setTimeout(r, 200));
        scanBar.style.width = "40%";
        scanStep.innerHTML = `<i class="fa-solid fa-route"></i> Step 2/4: Tracing reverse SMTP hops & resolving origin GeoIP...`;

        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ raw_email: emailContent })
        });

        scanBar.style.width = "75%";
        scanStep.innerHTML = `<i class="fa-solid fa-microchip"></i> Step 3/4: Executing AI heuristic classifier & MITRE mapping...`;

        const result = await response.json();

        scanBar.style.width = "100%";
        scanStep.innerHTML = `<i class="fa-solid fa-circle-check"></i> Step 4/4: Computing evidence hashes & compiling dossier...`;
        await new Promise(r => setTimeout(r, 150));

        if (result.status === "success") {
            currentAnalysisData = result;
            renderAllResults(result);
            showToast("Analysis complete. Threat scorecard & Geo trace updated!");
        } else {
            showToast(`Analysis Error: ${result.message}`);
        }
    } catch (error) {
        console.error("Scan error:", error);
        showToast("Error connecting to threat analysis backend.");
    } finally {
        btnContent.style.display = "flex";
        btnSpinner.style.display = "none";
        analyzeBtn.disabled = false;
        setTimeout(() => { scanBox.style.display = "none"; }, 800);
    }
}

/* ==========================================================================
   Render Analysis Results Across All Tabs
   ========================================================================== */
function renderAllResults(data) {
    const threat = data.threat;
    const geo = data.geolocation;
    const evidence = data.evidence;
    const parsed = threat.parsed_email;

    // 1. Left Panel Summary Card
    const headerSummary = document.getElementById("headerSummaryCard");
    headerSummary.style.display = "block";
    document.getElementById("summarySender").textContent = parsed.sender_email || parsed.sender_name || "Unknown";
    document.getElementById("summarySubject").textContent = parsed.subject || "No Subject";
    document.getElementById("summaryOriginIP").textContent = geo.origin_ip || "N/A";
    document.getElementById("summaryOriginGeo").textContent = `${geo.origin_geo.city || 'Unknown'}, ${geo.origin_geo.country || 'Unknown'}`;

    // 2. Tab 1: Threat Score & Gauge
    const score = threat.threat_score;
    document.getElementById("threatScoreDisplay").textContent = score;

    // Animate Circular Gauge (circumference = 2 * PI * 50 ≈ 314)
    const gaugeCircle = document.getElementById("gaugeCircle");
    const offset = 314 - (314 * (score / 100));
    gaugeCircle.style.strokeDashoffset = offset;
    gaugeCircle.style.stroke = threat.threat_color;

    // Risk Badge & Verdict
    const badge = document.getElementById("threatBadge");
    badge.textContent = threat.threat_level;
    badge.className = "risk-badge " + (score >= 75 ? "critical" : (score >= 50 ? "high" : "low"));

    const verdict = document.getElementById("threatVerdict");
    verdict.textContent = threat.verdict;
    verdict.style.color = threat.threat_color;

    document.getElementById("threatPrimaryTitle").textContent = threat.primary_threat;
    document.getElementById("threatSummaryDesc").textContent =
        `Detected ${threat.risk_factors.length} heuristic security factor(s). Originating from ${geo.origin_geo.city || 'Unknown'}, ${geo.origin_geo.country || 'Unknown'}.`;

    // Render MITRE ATT&CK Badges
    const mitreContainer = document.getElementById("mitreContainer");
    if (threat.mitre_attack && threat.mitre_attack.length > 0) {
        mitreContainer.innerHTML = threat.mitre_attack.map(m => `
            <div class="mitre-badge">
                <span class="mitre-id">${m.id}</span>
                <span class="mitre-name">${m.technique}</span>
            </div>
        `).join("");
    } else {
        mitreContainer.innerHTML = `<span class="empty-placeholder">No adversarial MITRE ATT&CK techniques observed.</span>`;
    }

    // Render Heuristic Risk Factors
    const riskContainer = document.getElementById("riskFactorsContainer");
    if (threat.risk_factors && threat.risk_factors.length > 0) {
        riskContainer.innerHTML = threat.risk_factors.map(r => `
            <div class="risk-item ${r.severity.toLowerCase()}">
                <div class="risk-item-header">
                    <span>${r.title}</span>
                    <span style="font-family: var(--font-code); font-size: 11px;">[${r.severity}]</span>
                </div>
                <div class="risk-item-desc">${r.description}</div>
            </div>
        `).join("");
    } else {
        riskContainer.innerHTML = `
            <div class="risk-item" style="border-left-color: var(--green-safe);">
                <div class="risk-item-header" style="color: var(--green-safe);">No High-Risk Heuristic Indicators Found</div>
                <div class="risk-item-desc">Headers and payload align with clean corporate messaging standards.</div>
            </div>
        `;
    }

    // Render Remediation Checklist
    const remContainer = document.getElementById("remediationContainer");
    remContainer.innerHTML = threat.recommendations.map(rec => `
        <li><i class="fa-solid fa-circle-check"></i> ${rec}</li>
    `).join("");

    // 3. Tab 2: Geolocation Hero Card & Leaflet Map
    document.getElementById("originLocationText").textContent =
        `${geo.origin_geo.city || 'Unknown'}, ${geo.origin_geo.country || 'Unknown'} (${geo.origin_geo.country_code || 'UN'})`;
    document.getElementById("originIPTag").innerHTML = `<i class="fa-solid fa-network-wired"></i> IP: ${geo.origin_ip}`;
    document.getElementById("originISPTag").innerHTML = `<i class="fa-solid fa-server"></i> ISP: ${geo.origin_geo.isp || 'N/A'}`;
    document.getElementById("originASNTag").innerHTML = `<i class="fa-solid fa-hashtag"></i> ASN: ${geo.origin_geo.asn || 'N/A'}`;
    document.getElementById("mapHopCounter").textContent = `Transit Hops: ${geo.hop_count}`;

    updateMapHops(geo.hops, geo.origin_geo);

    // Render Hop-by-Hop Timeline
    const hopsContainer = document.getElementById("hopsTimelineContainer");
    if (geo.hops && geo.hops.length > 0) {
        hopsContainer.innerHTML = geo.hops.map((h, i) => `
            <div class="hop-entry">
                <div class="hop-marker-dot ${i === 0 ? 'origin' : ''}"></div>
                <div class="hop-header">
                    <span style="color: ${i === 0 ? 'var(--red-threat)' : 'var(--cyan-accent)'};">
                        ${i === 0 ? '🚨 [ORIGIN SENDER]' : `🔄 [HOP #${h.hop_index}] ${h.role}`}
                    </span>
                    <span class="code-font" style="color: var(--text-main);">${h.ip}</span>
                </div>
                <div class="hop-geo">
                    <strong>Geo:</strong> ${h.geo.city || 'Unknown'}, ${h.geo.country || 'Unknown'} • <strong>Org:</strong> ${h.geo.org || h.geo.isp || 'N/A'}
                </div>
                <div style="font-family: var(--font-code); font-size: 11px; color: var(--text-dim); margin-top: 4px;">
                    ${h.header_snippet}
                </div>
            </div>
        `).join("");
    } else {
        hopsContainer.innerHTML = `<span class="empty-placeholder">No transit hop headers found.</span>`;
    }

    // 4. Tab 3: Forensics & IoCs
    document.getElementById("evidenceSha256").textContent = evidence.sha256 || "--";
    document.getElementById("evidenceMd5").textContent = evidence.md5 || "--";

    // Authentication Badges (SPF / DKIM / DMARC)
    const authResults = (parsed.auth_results || "").toLowerCase();
    updateAuthBadge("spfStatusBadge", "authSpfCard", authResults, "spf");
    updateAuthBadge("dkimStatusBadge", "authDkimCard", authResults, "dkim");
    updateAuthBadge("dmarcStatusBadge", "authDmarcCard", authResults, "dmarc");

    // Extracted IoCs Table
    const iocTbody = document.getElementById("iocTableBody");
    if (threat.iocs && threat.iocs.length > 0) {
        iocTbody.innerHTML = threat.iocs.map(ioc => `
            <tr>
                <td><strong>${ioc.type}</strong></td>
                <td><code>${ioc.value}</code></td>
                <td>${ioc.context}</td>
            </tr>
        `).join("");
    } else {
        iocTbody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No external IoCs extracted.</td></tr>`;
    }

    // Raw Headers Viewer
    let rawHeadersStr = "";
    for (const [k, v] of Object.entries(parsed.headers)) {
        rawHeadersStr += `${k}: ${v}\n`;
    }
    document.getElementById("rawHeadersViewer").textContent = rawHeadersStr || "No raw headers parsed.";

    // 5. Tab 4: Forensics Dossier Card
    activeCaseId = "DRAFT-" + Math.floor(1000 + Math.random() * 9000);
    document.getElementById("dossierCaseId").textContent = `CASE: ${activeCaseId}`;
    document.getElementById("dossierClass").textContent = threat.primary_threat;
    document.getElementById("dossierIP").textContent = geo.origin_ip;
    document.getElementById("dossierGeo").textContent = `${geo.origin_geo.city || 'Unknown'}, ${geo.origin_geo.country || 'Unknown'}`;
    document.getElementById("dossierTarget").textContent = parsed.to || "All Staff";

    const dossierPriority = document.getElementById("dossierPriority");
    if (score >= 75) {
        dossierPriority.textContent = "P1 - CRITICAL";
        dossierPriority.className = "priority-pill red";
    } else if (score >= 50) {
        dossierPriority.textContent = "P2 - HIGH";
        dossierPriority.className = "priority-pill red";
    } else {
        dossierPriority.textContent = "P3 - MEDIUM";
        dossierPriority.className = "priority-pill blue";
    }

    // Populate Printable Modal Content
    populatePrintableDossier(data);
}

function updateAuthBadge(badgeId, cardId, authStr, proto) {
    const badge = document.getElementById(badgeId);
    if (authStr.includes(`${proto}=pass`)) {
        badge.textContent = "PASS (VERIFIED)";
        badge.className = "auth-status badge-pass";
    } else if (authStr.includes(`${proto}=fail`) || authStr.includes(`${proto}=softfail`)) {
        badge.textContent = "FAIL (SPOOF / MISMATCH)";
        badge.className = "auth-status badge-fail";
    } else {
        badge.textContent = "NONE / MISSING";
        badge.className = "auth-status badge-neutral";
    }
}

/* ==========================================================================
   Tab Navigation
   ========================================================================== */
function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

    const btn = Array.from(document.querySelectorAll(".tab-btn")).find(b => b.getAttribute("onclick")?.includes(tabId));
    if (btn) btn.classList.add("active");

    const content = document.getElementById(tabId);
    if (content) content.classList.add("active");

    // Invalidate Leaflet Map size when switching to map tab
    if (tabId === "tabGeo" && threatMap) {
        setTimeout(() => { threatMap.invalidateSize(); }, 200);
    }
}

/* ==========================================================================
   Dispatch to Forensics & Docket Management
   ========================================================================== */
async function dispatchToForensics() {
    if (!currentAnalysisData) {
        showToast("Run threat analysis before dispatching.");
        return;
    }

    const notes = document.getElementById("analystNotesText").value.trim();
    const btn = document.getElementById("dispatchSocBtn");
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Dispatching...`;

    try {
        const res = await fetch("/api/report-forensics", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                threat_data: currentAnalysisData.threat,
                geo_data: currentAnalysisData.geolocation,
                raw_content: currentRawContent,
                analyst_notes: notes,
                reporter_id: "SOC Tier-1 Active Analyst"
            })
        });

        const data = await res.json();
        if (data.status === "success" && data.incident) {
            activeCaseId = data.incident.case_id;
            document.getElementById("dossierCaseId").textContent = `CASE: ${activeCaseId}`;
            document.getElementById("dossierStatus").textContent = "INVESTIGATING";
            showToast(`🚀 Dispatched to Forensics! Incident ${activeCaseId} registered.`);
            fetchIncidentsCount();
        } else {
            showToast(`Dispatch failed: ${data.message}`);
        }
    } catch (e) {
        console.error(e);
        showToast("Failed to dispatch incident to SOC queue.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> <strong>DISPATCH TO FORENSICS SOC</strong>`;
    }
}

async function fetchIncidentsCount() {
    try {
        const res = await fetch("/api/incidents");
        const data = await res.json();
        if (data.status === "success") {
            const count = data.count || 0;
            document.getElementById("docketBadgeCount").textContent = count;
        }
    } catch (e) {}
}

async function toggleDocketModal() {
    const modal = document.getElementById("docketModal");
    if (modal.style.display === "none" || modal.style.display === "") {
        modal.style.display = "flex";
        await renderDocketTable();
    } else {
        modal.style.display = "none";
    }
}

async function renderDocketTable() {
    const tbody = document.getElementById("incidentsTableBody");
    tbody.innerHTML = `<tr><td colspan="7" class="text-center"><i class="fa-solid fa-spinner fa-spin"></i> Loading cases...</td></tr>`;

    try {
        const res = await fetch("/api/incidents");
        const data = await res.json();
        if (data.status === "success" && data.incidents.length > 0) {
            tbody.innerHTML = data.incidents.map(inc => `
                <tr>
                    <td><strong class="code-font" style="color: var(--cyan-accent);">${inc.case_id}</strong></td>
                    <td style="font-size: 11px; color: var(--text-muted);">${inc.created_at}</td>
                    <td><strong>${inc.subject}</strong><br><span style="font-size: 11px; color: var(--text-dim);">${inc.primary_threat}</span></td>
                    <td><code style="color: var(--red-threat);">${inc.origin_ip}</code><br><span style="font-size: 11px;">${inc.origin_city}, ${inc.origin_country}</span></td>
                    <td><span class="score-pill" style="font-weight: 700; color: ${inc.threat_score >= 60 ? 'var(--red-threat)' : 'var(--green-safe)'};">${inc.threat_score}/100</span></td>
                    <td>
                        <select onchange="updateIncidentStatus('${inc.case_id}', this.value)" style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 4px; border-radius: 4px; font-size: 11px;">
                            <option value="INVESTIGATING" ${inc.status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option>
                            <option value="CONTAINED" ${inc.status === 'CONTAINED' ? 'selected' : ''}>CONTAINED</option>
                            <option value="CLOSED" ${inc.status === 'CLOSED' ? 'selected' : ''}>CLOSED</option>
                        </select>
                    </td>
                    <td>
                        <button class="btn-sm" onclick="downloadStixForCase('${inc.case_id}')" title="Download STIX 2.1 JSON"><i class="fa-solid fa-download"></i> STIX</button>
                    </td>
                </tr>
            `).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No incidents in docket.</td></tr>`;
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Failed to load cases.</td></tr>`;
    }
}

async function updateIncidentStatus(caseId, status) {
    try {
        await fetch(`/api/incidents/${caseId}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status })
        });
        showToast(`Case ${caseId} status updated to ${status}`);
    } catch (e) {
        showToast("Failed to update incident status.");
    }
}

/* ==========================================================================
   STIX 2.1 Export
   ========================================================================== */
function downloadStix() {
    if (activeCaseId.startsWith("DRAFT")) {
        // Auto dispatch first to create real ID
        dispatchToForensics().then(() => {
            if (!activeCaseId.startsWith("DRAFT")) {
                downloadStixForCase(activeCaseId);
            }
        });
    } else {
        downloadStixForCase(activeCaseId);
    }
}

function downloadStixForCase(caseId) {
    window.open(`/api/export-stix/${caseId}`, '_blank');
    showToast(`Downloaded STIX 2.1 Threat Intel for ${caseId}`);
}

/* ==========================================================================
   Printable Formal Forensic Dossier Modal
   ========================================================================== */
function togglePrintModal() {
    const modal = document.getElementById("printModal");
    if (modal.style.display === "none" || modal.style.display === "") {
        modal.style.display = "flex";
    } else {
        modal.style.display = "none";
    }
}

function openPrintableReport() {
    if (!currentAnalysisData) {
        showToast("Run analysis before printing report.");
        return;
    }
    populatePrintableDossier(currentAnalysisData);
    togglePrintModal();
}

function populatePrintableDossier(data) {
    const threat = data.threat;
    const geo = data.geolocation;
    const evidence = data.evidence;
    const parsed = threat.parsed_email;

    document.getElementById("printCaseId").textContent = activeCaseId;
    document.getElementById("printDate").textContent = `Date: ${new Date().toUTCString()}`;
    document.getElementById("printPrimaryThreat").textContent = threat.primary_threat;
    document.getElementById("printThreatScore").textContent = `${threat.threat_score}/100 (${threat.threat_level})`;
    document.getElementById("printSender").textContent = `${parsed.sender_name} <${parsed.sender_email}>`;
    document.getElementById("printRecipient").textContent = parsed.to;
    document.getElementById("printSubject").textContent = parsed.subject;

    document.getElementById("printOriginIP").textContent = geo.origin_ip;
    document.getElementById("printOriginGeo").textContent = `${geo.origin_geo.city || 'Unknown'}, ${geo.origin_geo.country || 'Unknown'}`;
    document.getElementById("printOriginISP").textContent = geo.origin_geo.isp || 'N/A';
    document.getElementById("printOriginASN").textContent = geo.origin_geo.asn || 'N/A';
    document.getElementById("printHopSummary").textContent = geo.transit_summary || `${geo.hop_count} transit hops`;

    document.getElementById("printSha256").textContent = evidence.sha256 || 'N/A';
    document.getElementById("printMd5").textContent = evidence.md5 || 'N/A';

    // Print IoCs
    const printIocContainer = document.getElementById("printIocContainer");
    if (threat.iocs && threat.iocs.length > 0) {
        printIocContainer.innerHTML = `
            <table class="rep-table">
                <thead>
                    <tr style="background: #f1f5f9; font-weight: bold;">
                        <td>Type</td><td>Defanged Indicator (IoC)</td><td>Context</td>
                    </tr>
                </thead>
                <tbody>
                    ${threat.iocs.map(i => `
                        <tr>
                            <td><strong>${i.type}</strong></td>
                            <td class="code-font">${i.value}</td>
                            <td>${i.context}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        `;
    } else {
        printIocContainer.innerHTML = `<p style="font-style: italic; color: #64748b;">No high-risk IoCs identified.</p>`;
    }

    // Print Remediation
    const printRemList = document.getElementById("printRemediationList");
    printRemList.innerHTML = threat.recommendations.map(r => `<li>${r}</li>`).join("");
}

/* ==========================================================================
   Utility Helpers (Clipboard, Toast)
   ========================================================================== */
function copyText(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
        navigator.clipboard.writeText(el.textContent.trim());
        showToast(`Copied ${elementId} to clipboard!`);
    }
}

function copyAllIoCs() {
    if (!currentAnalysisData || !currentAnalysisData.threat.iocs) {
        showToast("No IoCs to copy.");
        return;
    }
    const lines = currentAnalysisData.threat.iocs.map(i => `[${i.type}] ${i.value} (${i.context})`);
    navigator.clipboard.writeText(lines.join("\n"));
    showToast(`Copied ${lines.length} IoCs to clipboard!`);
}

function showToast(message) {
    const toast = document.getElementById("toastNotification");
    const msgEl = document.getElementById("toastMessage");
    msgEl.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 3500);
}