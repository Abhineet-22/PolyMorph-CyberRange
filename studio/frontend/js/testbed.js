// PolyMorph Studio — Testbed Range Controller (Technical Flat Theme)

let testbedStatusInterval = null;
let testbedExtractedInterval = null;

async function initTestbed() {
  await refreshTestbedStatus();
  await refreshExtractedArtifacts();

  if (!testbedStatusInterval) {
    testbedStatusInterval = setInterval(refreshTestbedStatus, 5000);
  }
  if (!testbedExtractedInterval) {
    testbedExtractedInterval = setInterval(refreshExtractedArtifacts, 4000);
  }
}

async function refreshTestbedStatus() {
  try {
    const res = await fetch("/api/testbed/status");
    const data = await res.json();
    const container = document.getElementById("testbedTiersStatusGrid");

    container.innerHTML = data.tiers.map(t => {
      const statusClass = t.online ? "bg-success" : "bg-danger";
      const statusDot = t.online ? "status-online" : "status-offline";
      const statusText = t.online ? `ONLINE (${t.latency_ms}ms)` : "OFFLINE / UNREACHABLE";
      const borderHighlight = t.online ? "border-color: #059669;" : "border-color: #991b1b;";

      return `
        <div class="col-md-4">
          <div class="tech-box h-100" style="${borderHighlight}">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="fw-bold text-white font-monospace small">${t.name}</span>
              <span class="badge ${statusClass} font-monospace">
                <span class="status-indicator ${statusDot}"></span>${statusText}
              </span>
            </div>
            <div class="small mb-1" style="color: var(--text-secondary);">
              Target: <code class="text-white">${t.base_url}</code>
            </div>
            <div class="small mb-2 font-monospace" style="color: var(--tech-cyan);">
              Vector: <span class="text-warning">${t.vector}</span>
            </div>
            <div class="small font-monospace text-truncate" style="color: var(--text-tertiary);">
              ${t.detail}
            </div>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to check testbed status:", err);
  }
}

/**
 * Physically attaches a binary artifact into the <input type="file"> via DataTransfer API
 * and updates the high-contrast Staged Payload inspection card.
 */
async function attachFileToTestbed(filename, tierOverride = null) {
  try {
    const res = await fetch(`/api/crafter/download/${filename}`);
    if (!res.ok) {
      console.warn("Could not retrieve artifact file:", filename);
      // Fallback: populate text field
      const nameInput = document.getElementById("testbedCustomFilename");
      if (nameInput) nameInput.value = filename;
      return;
    }

    const blob = await res.blob();
    const file = new File([blob], filename, { type: blob.type || "application/octet-stream" });

    // Physically bind file to the HTML5 file input via DataTransfer API
    const dt = new DataTransfer();
    dt.items.add(file);
    const fileInput = document.getElementById("testbedUploadFile");
    if (fileInput) {
      fileInput.files = dt.files;
    }

    // Keep text fallback in sync
    const nameInput = document.getElementById("testbedCustomFilename");
    if (nameInput) {
      nameInput.value = filename;
    }

    // Auto-detect tier
    const selTier = document.getElementById("testbedTierSelect");
    if (tierOverride && selTier) {
      selTier.value = String(tierOverride);
    } else if (selTier) {
      if (filename.includes("php") || filename.endsWith(".jpeg") || filename.endsWith(".jpg")) {
        selTier.value = "1";
      } else if (filename.includes("xss") || filename.includes("html")) {
        selTier.value = "2";
      } else if (filename.includes("slip") || filename.includes("zip")) {
        selTier.value = "3";
      }
    }

    // Update the visual Staged Payload Card
    const stagedCard = document.getElementById("testbedStagedCard");
    const stagedName = document.getElementById("testbedStagedName");
    const stagedSize = document.getElementById("testbedStagedSize");
    const stagedTier = document.getElementById("testbedStagedTier");
    const stagedStatus = document.getElementById("testbedStagedStatus");

    if (stagedCard) stagedCard.classList.remove("d-none");
    if (stagedName) stagedName.textContent = filename;
    if (stagedSize) stagedSize.textContent = `${blob.size.toLocaleString()} bytes`;
    if (stagedStatus) stagedStatus.textContent = "READY TO FIRE";

    const tierLabels = {
      "1": "Tier 1 — Legacy LAMP (JPEG+PHP -> LFI to RCE)",
      "2": "Tier 2 — Modern MERN (PNG+HTML Stored XSS)",
      "3": "Tier 3 — Cloud-Native S3 (Worker Diff Sink)",
    };
    if (stagedTier && selTier) {
      stagedTier.textContent = tierLabels[selTier.value] || `Tier ${selTier.value}`;
    }
  } catch (err) {
    console.error("Failed to attach binary artifact:", err);
  }
}

/**
 * Quick-loads a verified exploit preset from disk into the firing chamber.
 */
async function loadTestbedPreset(filename, tier) {
  await attachFileToTestbed(filename, tier);
}

/**
 * Handles manual user file picker uploads.
 */
function onTestbedFileSelected(input) {
  if (input.files && input.files[0]) {
    const f = input.files[0];
    const nameInput = document.getElementById("testbedCustomFilename");
    if (nameInput) nameInput.value = f.name;

    const stagedCard = document.getElementById("testbedStagedCard");
    const stagedName = document.getElementById("testbedStagedName");
    const stagedSize = document.getElementById("testbedStagedSize");
    const stagedTier = document.getElementById("testbedStagedTier");
    const stagedStatus = document.getElementById("testbedStagedStatus");

    if (stagedCard) stagedCard.classList.remove("d-none");
    if (stagedName) stagedName.textContent = f.name;
    if (stagedSize) stagedSize.textContent = `${f.size.toLocaleString()} bytes`;
    if (stagedStatus) stagedStatus.textContent = "MANUALLY LOADED";

    const selTier = document.getElementById("testbedTierSelect");
    const tierLabels = {
      "1": "Tier 1 — Legacy LAMP (JPEG+PHP -> LFI to RCE)",
      "2": "Tier 2 — Modern MERN (PNG+HTML Stored XSS)",
      "3": "Tier 3 — Cloud-Native S3 (Worker Diff Sink)",
    };
    if (stagedTier && selTier) {
      stagedTier.textContent = tierLabels[selTier.value] || `Tier ${selTier.value}`;
    }
  }
}

function onTestbedTierChanged() {
  const selTier = document.getElementById("testbedTierSelect");
  const stagedTier = document.getElementById("testbedStagedTier");
  const tierLabels = {
    "1": "Tier 1 — Legacy LAMP (JPEG+PHP -> LFI to RCE)",
    "2": "Tier 2 — Modern MERN (PNG+HTML Stored XSS)",
    "3": "Tier 3 — Cloud-Native S3 (Worker Diff Sink)",
  };
  if (stagedTier && selTier) {
    stagedTier.textContent = tierLabels[selTier.value] || `Tier ${selTier.value}`;
  }
}

async function fireTestbedPayload() {
  const tier = document.getElementById("testbedTierSelect").value;
  const filename = document.getElementById("testbedCustomFilename").value.trim();
  const fileInput = document.getElementById("testbedUploadFile").files[0];

  if (!filename && !fileInput) {
    alert("Please select a pre-built preset, craft a polyglot, or attach an attack file.");
    return;
  }

  const formData = new FormData();
  formData.append("tier", tier);
  if (fileInput) {
    formData.append("file", fileInput);
  }
  if (filename) {
    formData.append("filename", filename);
  }

  const btn = document.getElementById("testbedFireBtn");
  const spinner = document.getElementById("testbedSpinner");
  const resultCard = document.getElementById("testbedResultCard");

  btn.disabled = true;
  spinner.classList.remove("d-none");
  resultCard.classList.add("d-none");

  try {
    const res = await fetch("/api/testbed/fire", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Firing request failed");
    }

    renderFiringResult(data);
    resultCard.classList.remove("d-none");
    refreshExtractedArtifacts();
  } catch (err) {
    alert("Testbed Firing Error: " + err.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add("d-none");
  }
}

function renderFiringResult(data) {
  const isCritical = data.verdict && (
    data.verdict.includes("RCE") ||
    data.verdict.includes("CONFIRMED") ||
    data.verdict.includes("EXTRACTED")
  );

  document.getElementById("testbedVerdictBadge").textContent = data.verdict;
  document.getElementById("testbedVerdictBadge").className = isCritical
    ? "badge bg-danger font-monospace fs-6"
    : "badge bg-warning text-dark font-monospace fs-6";

  document.getElementById("testbedExecTime").textContent = `EXECUTION TIME: ${data.duration_ms} ms`;
  document.getElementById("testbedRawResult").textContent = JSON.stringify(data, null, 2);

  const linksContainer = document.getElementById("testbedExecutionLinks");
  linksContainer.innerHTML = "";

  if (data.lfi_url) {
    linksContainer.innerHTML += `
      <a href="${data.lfi_url}" target="_blank" class="btn btn-sm btn-outline-danger font-monospace me-2">
        OPEN LFI RCE URL (cmd=id) &rarr;
      </a>
    `;
  }
  if (data.xss_url) {
    linksContainer.innerHTML += `
      <a href="${data.xss_url}" target="_blank" class="btn btn-sm btn-outline-warning font-monospace me-2">
        OPEN STORED XSS URL &rarr;
      </a>
    `;
  }
}

async function refreshExtractedArtifacts() {
  try {
    const res = await fetch("/api/testbed/extracted");
    const data = await res.json();
    const container = document.getElementById("testbedExtractedList");

    const t2Files = data.tier2 || [];
    const t3Files = data.tier3 || [];

    if (t2Files.length === 0 && t3Files.length === 0) {
      container.innerHTML = `<span class="small font-monospace" style="color: var(--text-tertiary);">No extracted files present in testbed worker sinks.</span>`;
      return;
    }

    let html = "";
    if (t2Files.length > 0) {
      html += `<div class="fw-bold font-monospace small mb-2" style="color: var(--tech-cyan);">Tier 2 MERN (adm-zip worker sink):</div>`;
      html += t2Files.map(f => `
        <div class="tech-box-subtle mb-2">
          <div class="d-flex justify-content-between align-items-center">
            <strong class="text-warning font-monospace small">${f.name || f}</strong>
            <span class="badge bg-secondary font-monospace">adm-zip</span>
          </div>
          ${f.preview ? `<pre class="mt-2 mb-0 p-1 font-monospace small">${f.preview}</pre>` : ""}
        </div>
      `).join("");
    }

    if (t3Files.length > 0) {
      html += `<div class="fw-bold font-monospace small mb-2 mt-3" style="color: var(--tech-cyan);">Tier 3 Cloud-Native (zipfile sink):</div>`;
      html += t3Files.map(f => `
        <div class="tech-box-subtle mb-2">
          <div class="d-flex justify-content-between align-items-center">
            <strong class="text-warning font-monospace small">${f.name || f}</strong>
            <span class="badge bg-danger font-monospace">${f.size ? f.size + " B" : "Extracted"}</span>
          </div>
          ${f.preview ? `<pre class="mt-2 mb-0 p-1 font-monospace small">${f.preview}</pre>` : ""}
        </div>
      `).join("");
    }

    container.innerHTML = html;
  } catch (err) {
    // silently catch polling errors
  }
}

async function clearTestbedDirs() {
  if (!confirm("Wipe all staged payloads and worker extracted directories on Tier 2 & Tier 3?")) return;
  try {
    const res = await fetch("/api/testbed/clear", { method: "POST" });
    const data = await res.json();
    alert("Cleaned testbed extraction workspaces successfully.");
    refreshExtractedArtifacts();
  } catch (err) {
    alert("Directory clean failed: " + err.message);
  }
}
