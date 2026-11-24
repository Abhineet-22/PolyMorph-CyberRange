// PolyMorph Studio — Reconnaissance Controller (Technical Flat Theme)

let reconTimerInterval = null;
let reconLogTimeouts = [];

async function runReconScan() {
  const urlInput = document.getElementById("reconUrlInput").value.trim();
  if (!urlInput) {
    alert("Please enter a target URL (e.g. http://localhost:8081) or click a testbed preset.");
    return;
  }

  // Use values if entered, otherwise fallback to placeholder defaults
  const depth = parseInt(document.getElementById("reconDepthInput").value, 10) || 2;
  const pages = parseInt(document.getElementById("reconPagesInput").value, 10) || 25;
  const probeCommon = document.getElementById("reconProbeCommon").checked;

  const btn = document.getElementById("reconScanBtn");
  const spinner = document.getElementById("reconSpinner");
  const resultsArea = document.getElementById("reconResultsArea");
  const emptyPrompt = document.getElementById("reconEmptyPrompt");
  const loadingState = document.getElementById("reconLoadingState");
  const bufferTarget = document.getElementById("reconBufferTarget");
  const bufferTimer = document.getElementById("reconBufferTimer");
  const terminalLog = document.getElementById("reconTerminalLog");

  btn.disabled = true;
  spinner.classList.remove("d-none");
  if (emptyPrompt) emptyPrompt.classList.add("d-none");
  if (resultsArea) resultsArea.classList.add("d-none");
  if (loadingState) loadingState.classList.remove("d-none");

  // Reset & start buffer state
  bufferTarget.textContent = urlInput;
  bufferTimer.textContent = "0.0s";
  terminalLog.innerHTML = "";

  const startTime = Date.now();
  if (reconTimerInterval) clearInterval(reconTimerInterval);
  reconTimerInterval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    bufferTimer.textContent = `${elapsed}s`;
  }, 100);

  // Clear previous log timeouts
  reconLogTimeouts.forEach(t => clearTimeout(t));
  reconLogTimeouts = [];

  function addLogLine(text, colorClass = "text-info") {
    const el = document.createElement("div");
    el.className = `recon-log-line ${colorClass}`;
    el.textContent = text;
    terminalLog.appendChild(el);
    if (terminalLog.children.length > 5) {
      terminalLog.removeChild(terminalLog.firstChild);
    }
  }

  // Sequence realistic technical probe logs
  const logs = [
    { delay: 0, text: `> [CONNECT] Initiating TCP/HTTP handshake to ${urlInput}...`, color: "text-cyan" },
    { delay: 400, text: `> [BANNER] Querying HTTP response headers & server tokens...`, color: "text-info" },
    { delay: 900, text: `> [CRAWL] Parsing HTML DOM: anchors, forms & input elements (depth: ${depth})...`, color: "text-white" },
    { delay: 1600, text: `> [PROBE] Dispatching 20 parallel threads for discovery endpoints...`, color: "text-warning" },
    { delay: 2400, text: `> [AUDIT] Evaluating security header directives (CSP, CORS, HSTS)...`, color: "text-secondary" },
    { delay: 3200, text: `> [CORRELATE] Correlating detected stack signatures with polyglot contracts...`, color: "text-info" },
    { delay: 4000, text: `> [FINALIZE] Aggregating telemetry and synthesis recommendations...`, color: "text-cyan" },
  ];

  logs.forEach(l => {
    const t = setTimeout(() => addLogLine(l.text, l.color), l.delay);
    reconLogTimeouts.push(t);
  });

  try {
    const res = await fetch("/api/recon/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: urlInput,
        depth: depth,
        pages: pages,
        timeout: 8,
        probe_common: probeCommon,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Scan request failed");
    }

    const data = await res.json();

    // Log completion
    addLogLine(`> [COMPLETE] Telemetry received (${data.pages_crawled} pages, ${data.duration_seconds}s). Rendering...`, "text-success");

    // Brief delay to allow the user to see the successful buffer state transition
    await new Promise(r => setTimeout(r, 350));

    renderReconResults(data);
    if (loadingState) loadingState.classList.add("d-none");
    if (resultsArea) resultsArea.classList.remove("d-none");
  } catch (err) {
    if (loadingState) loadingState.classList.add("d-none");
    if (emptyPrompt) emptyPrompt.classList.remove("d-none");
    alert("Recon Scan Failed: " + err.message);
  } finally {
    if (reconTimerInterval) clearInterval(reconTimerInterval);
    reconLogTimeouts.forEach(t => clearTimeout(t));
    btn.disabled = false;
    spinner.classList.add("d-none");
  }
}

function setReconPreset(url) {
  document.getElementById("reconUrlInput").value = url;
}

function renderReconResults(data) {
  // Target Overview
  document.getElementById("reconTargetDisplay").textContent = data.target;
  document.getElementById("reconDurationDisplay").textContent = `${data.duration_seconds}s`;
  document.getElementById("reconPagesDisplay").textContent = data.pages_crawled;

  // Server Headers
  const hdrContainer = document.getElementById("reconHeadersContainer");
  if (data.server_info && Object.keys(data.server_info).length > 0) {
    hdrContainer.innerHTML = Object.entries(data.server_info)
      .map(([k, v]) => `<div><span class="text-cyan fw-bold">${k}:</span> <span class="text-white">${v}</span></div>`)
      .join("");
  } else {
    hdrContainer.innerHTML = `<span style="color: var(--text-tertiary);">No banner headers returned.</span>`;
  }

  // Tech Stack Evidence Badges
  const techContainer = document.getElementById("reconTechContainer");
  if (data.tech_summary && Object.keys(data.tech_summary).length > 0) {
    techContainer.innerHTML = Object.entries(data.tech_summary)
      .map(([tech, weight]) => `
        <span class="badge badge-tech px-2 py-1 me-1 mb-1 font-monospace">
          ${tech} <span class="badge bg-secondary ms-1">w:${weight}</span>
        </span>
      `).join("");
  } else {
    techContainer.innerHTML = `<span style="color: var(--text-tertiary);">No technology signatures matched.</span>`;
  }

  // Security Gaps
  const gapsTable = document.getElementById("reconGapsTableBody");
  if (data.security_gaps && data.security_gaps.length > 0) {
    gapsTable.innerHTML = data.security_gaps.map(g => {
      const sevClass = g.severity === "high" ? "badge bg-danger" : g.severity === "medium" ? "badge bg-warning text-dark" : "badge bg-secondary";
      return `
        <tr>
          <td><code class="text-cyan">${g.header}</code></td>
          <td><span class="${sevClass}">${g.severity.toUpperCase()}</span></td>
          <td style="color: var(--text-secondary); font-size: 0.85rem;">${g.gap}</td>
        </tr>
      `;
    }).join("");
  } else {
    gapsTable.innerHTML = `<tr><td colspan="3" class="text-success small font-monospace">✓ All checked security headers verified present.</td></tr>`;
  }

  // Upload Endpoints
  const uploadContainer = document.getElementById("reconUploadsContainer");
  if (data.upload_endpoints && data.upload_endpoints.length > 0) {
    uploadContainer.innerHTML = data.upload_endpoints.map(ep => `
      <div class="tech-box-subtle mb-2">
        <div class="d-flex justify-content-between align-items-center mb-1">
          <strong class="text-warning font-monospace">${ep.url}</strong>
          <span class="badge bg-primary font-monospace">${ep.method}</span>
        </div>
        <div class="small" style="color: var(--text-secondary);">
          Enctype: <code>${ep.enctype}</code> | Input: <code>${ep.field_name}</code>
          ${ep.accept && ep.accept.length ? ` | Accepts: <span class="text-info">${ep.accept.join(", ")}</span>` : ""}
        </div>
      </div>
    `).join("");
  } else {
    uploadContainer.innerHTML = `<p class="small mb-0" style="color: var(--text-tertiary);">No multipart upload forms detected in scan.</p>`;
  }

  // ── Content Processing Surfaces ────────────────────────────────────────────
  const surfacesContainer = document.getElementById("reconSurfacesContainer");
  const surfaceCountBadge = document.getElementById("reconSurfaceCount");
  const surfaces = data.content_surfaces || [];

  if (surfaceCountBadge) surfaceCountBadge.textContent = surfaces.length;

  const categoryIcons = {
    media_serving:  { icon: "🖼", label: "Media Serving",       color: "text-warning"  },
    doc_processing: { icon: "📄", label: "Document Processing",  color: "text-danger"   },
    content_embed:  { icon: "🔗", label: "Content Embedding",    color: "text-info"     },
    api_ingestion:  { icon: "⚙", label: "API Ingestion",        color: "text-cyan"     },
    cloud_storage:  { icon: "☁", label: "Cloud Storage",        color: "text-info"     },
    download_serve: { icon: "⬇", label: "File Download/Serve",  color: "text-warning"  },
  };

  if (surfaces.length > 0 && surfacesContainer) {
    surfacesContainer.innerHTML = surfaces.map(surf => {
      const meta = categoryIcons[surf.category] || { icon: "🔍", label: surf.category, color: "text-white" };
      const sevClass = surf.severity === "high" ? "badge bg-danger" : surf.severity === "medium" ? "badge bg-warning text-dark" : "badge bg-secondary";
      const hostFmt = surf.category === "doc_processing" ? "pdf"
                    : surf.category === "cloud_storage"  ? "jpeg"
                    : surf.category === "api_ingestion"  ? "jpeg"
                    : "jpeg";
      const payFmt  = surf.category === "doc_processing" ? "zip"
                    : surf.category === "cloud_storage"  ? "zip"
                    : "html";
      const strategy = surf.category === "cloud_storage" || surf.category === "doc_processing" ? "append" : "inject";

      const exploitBadge = surf.exploitability === "latent"
        ? `<span class="badge bg-secondary font-monospace">LATENT / SUPPLY-CHAIN</span>`
        : `<span class="badge bg-success font-monospace">ACTIVE DELIVERY</span>`;
      const endpointsList = surf.endpoints && surf.endpoints.length > 0 ? surf.endpoints : [surf.url];

      return `
        <div class="tech-box mb-3 border-start border-3 ps-3" style="border-color: var(--tech-cyan) !important;">
          <div class="d-flex justify-content-between align-items-start mb-2">
            <div>
              <span class="me-2">${meta.icon}</span>
              <span class="fw-bold font-monospace ${meta.color}">${surf.label}</span>
              <span class="ms-2 small font-monospace" style="color: var(--text-tertiary);">[${surf.category}]</span>
            </div>
            <div class="d-flex gap-2 align-items-center flex-shrink-0 ms-2">
              ${exploitBadge}
              ${surf.cve_ref ? `<span class="badge bg-danger font-monospace">${surf.cve_ref}</span>` : ""}
              <span class="${sevClass}">${surf.severity.toUpperCase()}</span>
            </div>
          </div>
          <div class="mb-1">
            <span class="small font-monospace" style="color: var(--text-tertiary);">EVIDENCE: </span>
            <code class="small text-cyan">${surf.evidence}</code>
          </div>
          <p class="small mb-2" style="color: var(--text-secondary); line-height: 1.4;">${surf.risk_note}</p>
          ${surf.delivery_chain ? `
            <div class="small font-monospace mb-2 p-2 rounded" style="background: rgba(15, 23, 42, 0.75); border-left: 3px solid ${surf.exploitability === 'active' ? '#10b981' : '#64748b'};">
              <span class="fw-bold text-uppercase" style="color: ${surf.exploitability === 'active' ? '#34d399' : '#94a3b8'}; font-size: 0.72rem;">Delivery Chain:</span>
              <span class="text-white d-block mt-1" style="font-size: 0.78rem;">${surf.delivery_chain}</span>
            </div>
          ` : ""}
          <div class="mb-2 p-2 rounded" style="background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-subtle);">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="small font-monospace text-uppercase fw-bold" style="color: var(--tech-cyan); font-size: 0.72rem;">
                Mapped Target Endpoints (${endpointsList.length}):
              </span>
            </div>
            <div class="d-flex flex-wrap gap-1">
              ${endpointsList.map(ep => `<code class="p-1 px-2 text-white bg-dark border rounded font-monospace small" style="border-color: #334155 !important;">${ep}</code>`).join("")}
            </div>
          </div>
          <div class="d-flex justify-content-between align-items-center pt-2 border-top" style="border-color: var(--border-subtle) !important;">
            <span class="small font-monospace" style="color: var(--text-tertiary);">Primary Surface: <code class="text-white">${surf.url.length > 50 ? surf.url.substring(0, 50) + "…" : surf.url}</code></span>
            <button class="btn btn-sm btn-outline-cyan py-1 px-3 font-monospace fw-bold"
              onclick="sendToCrafter('${hostFmt}', '${payFmt}', '${strategy}')">
              CRAFT POLYGLOT &rarr;
            </button>
          </div>
        </div>
      `;
    }).join("");
  } else if (surfacesContainer) {
    surfacesContainer.innerHTML = `
      <div class="d-flex align-items-center gap-2 font-monospace small" style="color: var(--text-tertiary);">
        <span>✓</span>
        <span>No additional content processing surfaces detected. Classic upload endpoint attack surface only.</span>
      </div>`;
  }

  // Recommendations
  const recsContainer = document.getElementById("reconRecsContainer");
  if (data.recommendations && data.recommendations.length > 0) {
    recsContainer.innerHTML = data.recommendations.map(rec => {
      const riskClass = rec.risk.includes("RCE") ? "badge-risk-rce" : rec.risk.includes("XSS") ? "badge-risk-xss" : "badge-risk-diff";
      const hostFmt = rec.host_formats && rec.host_formats.length ? rec.host_formats[0] : "png";
      const payloadFmt = rec.payload_format || (rec.trigger.toLowerCase().includes("php") ? "php" : rec.trigger.toLowerCase().includes("archive") ? "zip" : "html");
      const exploitBadge = rec.exploitability === "latent"
        ? `<span class="badge bg-secondary font-monospace">LATENT VECTOR</span>`
        : `<span class="badge bg-success font-monospace">ACTIVE VECTOR</span>`;

      return `
        <div class="tech-box mb-3">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <span class="fw-bold text-white font-monospace">${rec.trigger}</span>
            <div class="d-flex gap-2 align-items-center">
              ${exploitBadge}
              <span class="badge ${riskClass}">${rec.risk}</span>
              <span class="badge bg-secondary font-monospace">${rec.strategy.toUpperCase()}</span>
            </div>
          </div>
          <p class="small mb-2" style="color: var(--text-secondary);">${rec.payload_note}</p>
          ${rec.endpoints && rec.endpoints.length > 0 ? `
            <div class="mb-2 p-2 rounded" style="background: rgba(15, 23, 42, 0.75); border: 1px solid var(--border-subtle);">
              <span class="small font-monospace text-uppercase fw-bold d-block mb-1" style="color: var(--text-warning); font-size: 0.72rem;">
                Target Demo Endpoints (${rec.endpoints.length}):
              </span>
              <div class="d-flex flex-wrap gap-1">
                ${rec.endpoints.map(ep => `<code class="p-1 px-2 text-warning bg-dark border rounded font-monospace small" style="border-color: #334155 !important;">${ep}</code>`).join("")}
              </div>
            </div>
          ` : ""}
          <div class="d-flex justify-content-between align-items-center pt-2 border-top" style="border-color: var(--border-subtle) !important;">
            <span class="small font-monospace" style="color: var(--text-tertiary);">Carrier Formats: <code class="text-white">${rec.host_formats.join(", ")}</code></span>
            <button class="btn btn-sm btn-outline-warning py-1 px-3 font-monospace fw-bold"
              onclick="sendToCrafter('${hostFmt}', '${payloadFmt}', '${rec.strategy}')">
              CRAFT THIS POLYGLOT &rarr;
            </button>
          </div>
        </div>
      `;
    }).join("");
  } else {
    recsContainer.innerHTML = `<p class="small mb-0" style="color: var(--text-tertiary);">No polyglot strategies recommended for target.</p>`;
  }
}

async function sendToCrafter(hostFmt, payloadFmt, strategy) {
  // Ensure crafter format options & sample files are loaded before setting values
  if (typeof initCrafter === "function") {
    await initCrafter();
  }

  // Set dropdowns in crafter tab
  const selA = document.getElementById("crafterHostFmt");
  const selB = document.getElementById("crafterPayloadFmt");
  const selS = document.getElementById("crafterStrategy");
  const sampleA = document.getElementById("crafterSampleA");
  const sampleB = document.getElementById("crafterSampleB");
  const fileA = document.getElementById("crafterFileA");
  const fileB = document.getElementById("crafterFileB");

  if (fileA) fileA.value = "";
  if (fileB) fileB.value = "";

  if (selA) selA.value = hostFmt.toLowerCase();
  if (selB) selB.value = payloadFmt.toLowerCase();
  if (selS) selS.value = (strategy && strategy !== "auto") ? strategy.toLowerCase() : "auto";

  // Auto-align sample files to matching formats
  if (sampleA) {
    const targetA = hostFmt.toLowerCase();
    for (let opt of sampleA.options) {
      if (opt.value && (opt.value.includes(`sample.${targetA}`) || opt.value.endsWith(`.${targetA}`) || (targetA === "jpeg" && opt.value.endsWith(".jpg")))) {
        sampleA.value = opt.value;
        break;
      }
    }
  }

  if (sampleB) {
    const targetB = payloadFmt.toLowerCase();
    for (let opt of sampleB.options) {
      if (opt.value && (
        (targetB === "html" && (opt.value.includes("xss") || opt.value.includes("payload.html") || opt.value.endsWith(".html"))) ||
        (targetB === "php" && (opt.value.includes("payload.php") || opt.value.includes("shell") || opt.value.endsWith(".php"))) ||
        (targetB === "zip" && (opt.value.includes("payload.zip") || opt.value.includes("slip") || opt.value.endsWith(".zip"))) ||
        opt.value.endsWith(`.${targetB}`)
      )) {
        sampleB.value = opt.value;
        break;
      }
    }
  }

  // Trigger pair analysis
  if (typeof onCrafterPairChanged === "function") {
    await onCrafterPairChanged();
  }

  // Switch to crafter tab
  const crafterTabBtn = document.getElementById("tab-crafter-btn");
  if (crafterTabBtn) {
    bootstrap.Tab.getOrCreateInstance(crafterTabBtn).show();
  }
}
