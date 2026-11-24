// PolyMorph Studio — Polyglot Crafter Controller (Technical Flat Theme)

let activeBuiltFilename = null;
let crafterInitialized = false;
let crafterInitPromise = null;

async function initCrafter() {
  if (crafterInitialized) return;
  if (!crafterInitPromise) {
    crafterInitPromise = (async () => {
      await loadFormats();
      await loadSampleFiles();
      crafterInitialized = true;
      await onCrafterPairChanged();
    })();
  }
  return crafterInitPromise;
}

async function loadFormats() {
  try {
    const res = await fetch("/api/crafter/formats");
    const data = await res.json();
    const selA = document.getElementById("crafterHostFmt");
    const selB = document.getElementById("crafterPayloadFmt");

    const currentA = selA.value;
    const currentB = selB.value;

    const options = data.formats.map(f => `<option value="${f.name}">${f.name.toUpperCase()} (${f.extensions.join(", ")})</option>`).join("");
    selA.innerHTML = options;
    selB.innerHTML = options;

    // Preserve if already set, otherwise default
    selA.value = currentA || "png";
    selB.value = currentB || "zip";
  } catch (err) {
    console.error("Failed to load format registry:", err);
  }
}

async function loadSampleFiles() {
  try {
    const res = await fetch("/api/crafter/samples");
    const data = await res.json();
    const selA = document.getElementById("crafterSampleA");
    const selB = document.getElementById("crafterSampleB");

    const currentA = selA.value;
    const currentB = selB.value;

    const hostOpts = [`<option value="">-- Or Choose Stored Sample File --</option>`];
    const payloadOpts = [`<option value="">-- Or Choose Stored Sample File --</option>`];

    data.samples.forEach(s => {
      const opt = `<option value="${s.filename}">${s.filename} (${s.size_bytes} B)</option>`;
      if (s.filename.includes("sample") || s.filename.endsWith(".png") || s.filename.endsWith(".jpg") || s.filename.endsWith(".jpeg") || s.filename.endsWith(".pdf")) {
        hostOpts.push(opt);
      }
      if (s.filename.includes("payload") || s.filename.includes("shell") || s.filename.includes("xss") || s.filename.includes("slip") || s.filename.endsWith(".zip") || s.filename.endsWith(".php") || s.filename.endsWith(".html")) {
        payloadOpts.push(opt);
      }
    });

    selA.innerHTML = hostOpts.join("");
    selB.innerHTML = payloadOpts.join("");

    // Set smart defaults or preserve current
    if (currentA && data.samples.some(s => s.filename === currentA)) {
      selA.value = currentA;
    } else if (data.samples.some(s => s.filename === "sample.png")) {
      selA.value = "sample.png";
    }

    if (currentB && data.samples.some(s => s.filename === currentB)) {
      selB.value = currentB;
    } else if (data.samples.some(s => s.filename === "payload.zip")) {
      selB.value = "payload.zip";
    }
  } catch (err) {
    console.error("Failed to load sample library:", err);
  }
}

async function onCrafterPairChanged() {
  const fmtA = document.getElementById("crafterHostFmt").value;
  const fmtB = document.getElementById("crafterPayloadFmt").value;
  const analysisBox = document.getElementById("crafterPairAnalysis");
  const sampleA = document.getElementById("crafterSampleA");
  const sampleB = document.getElementById("crafterSampleB");

  if (!fmtA || !fmtB) return;

  // Auto-align sample files if current selection does not match new format
  if (sampleA && (!sampleA.value || !sampleA.value.endsWith(fmtA === "jpeg" ? ".jpg" : `.${fmtA}`))) {
    for (let opt of sampleA.options) {
      if (opt.value && (opt.value.includes(`sample.${fmtA}`) || opt.value.endsWith(`.${fmtA}`) || (fmtA === "jpeg" && opt.value.endsWith(".jpg")))) {
        sampleA.value = opt.value;
        break;
      }
    }
  }

  if (sampleB && (!sampleB.value || !sampleB.value.endsWith(`.${fmtB}`))) {
    for (let opt of sampleB.options) {
      if (opt.value && (
        (fmtB === "html" && (opt.value.includes("xss") || opt.value.includes("payload.html") || opt.value.endsWith(".html"))) ||
        (fmtB === "php" && (opt.value.includes("payload.php") || opt.value.includes("shell") || opt.value.endsWith(".php"))) ||
        (fmtB === "zip" && (opt.value.includes("payload.zip") || opt.value.includes("slip") || opt.value.endsWith(".zip"))) ||
        opt.value.endsWith(`.${fmtB}`)
      )) {
        sampleB.value = opt.value;
        break;
      }
    }
  }

  try {
    const res = await fetch(`/api/crafter/info?fmt_a=${fmtA}&fmt_b=${fmtB}`);
    const data = await res.json();
    analysisBox.innerHTML = `
      <span class="tech-metric-label mb-1">Pair Compatibility Specification:</span>
      <div class="tech-box-subtle font-monospace small" style="color: #93c5fd; white-space: pre-wrap; line-height: 1.45;">
${data.analysis}
      </div>
    `;
  } catch (err) {
    analysisBox.innerHTML = `<span class="text-danger small font-monospace">Error analyzing format contract: ${err.message}</span>`;
  }
}

async function executePolyglotBuild() {
  const fmtA = document.getElementById("crafterHostFmt").value;
  const fmtB = document.getElementById("crafterPayloadFmt").value;
  const strategy = document.getElementById("crafterStrategy").value;

  const fileInputA = document.getElementById("crafterFileA").files[0];
  const fileInputB = document.getElementById("crafterFileB").files[0];
  const sampleA = document.getElementById("crafterSampleA").value;
  const sampleB = document.getElementById("crafterSampleB").value;

  if (!fileInputA && !sampleA) {
    alert("Please select or upload Host File A.");
    return;
  }
  if (!fileInputB && !sampleB) {
    alert("Please select or upload Payload File B.");
    return;
  }

  const formData = new FormData();
  formData.append("fmt_a", fmtA);
  formData.append("fmt_b", fmtB);
  if (strategy && strategy !== "auto") {
    formData.append("strategy", strategy);
  }

  if (fileInputA) {
    formData.append("file_a", fileInputA);
  } else {
    formData.append("sample_a", sampleA);
  }

  if (fileInputB) {
    formData.append("file_b", fileInputB);
  } else {
    formData.append("sample_b", sampleB);
  }

  const btn = document.getElementById("crafterBuildBtn");
  const spinner = document.getElementById("crafterSpinner");
  const resultCard = document.getElementById("crafterResultCard");
  const emptyPrompt = document.getElementById("crafterEmptyPrompt");

  btn.disabled = true;
  spinner.classList.remove("d-none");
  resultCard.classList.add("d-none");

  try {
    const res = await fetch("/api/crafter/build", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      throw new Error(data.error || "Synthesis failed");
    }

    renderCrafterResult(data);
    if (emptyPrompt) emptyPrompt.classList.add("d-none");
    resultCard.classList.remove("d-none");
  } catch (err) {
    alert("Synthesis Error: " + err.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add("d-none");
  }
}

function renderCrafterResult(data) {
  activeBuiltFilename = data.filename;

  document.getElementById("crafterOutFilename").textContent = data.filename;
  document.getElementById("crafterOutSize").textContent = `${data.size_bytes.toLocaleString()} bytes`;
  document.getElementById("crafterOutStrat").textContent = data.strategy.toUpperCase();
  document.getElementById("crafterOutSha").textContent = data.sha256;

  // Validation pills
  const valABox = document.getElementById("crafterValA");
  const valBBox = document.getElementById("crafterValB");

  valABox.innerHTML = data.validation_a.valid
    ? `<span class="badge bg-success font-monospace me-2">VALID // ${data.fmt_a.toUpperCase()}</span> <span class="small" style="color: var(--text-secondary);">${data.validation_a.detail}</span>`
    : `<span class="badge bg-danger font-monospace me-2">INVALID // ${data.fmt_a.toUpperCase()}</span> <span class="small" style="color: var(--text-secondary);">${data.validation_a.detail}</span>`;

  valBBox.innerHTML = data.validation_b.valid
    ? `<span class="badge bg-success font-monospace me-2">VALID // ${data.fmt_b.toUpperCase()}</span> <span class="small" style="color: var(--text-secondary);">${data.validation_b.detail}</span>`
    : `<span class="badge bg-danger font-monospace me-2">INVALID // ${data.fmt_b.toUpperCase()}</span> <span class="small" style="color: var(--text-secondary);">${data.validation_b.detail}</span>`;

  // Overall verdict badge
  const verdictBadge = document.getElementById("crafterOverallVerdict");
  if (data.both_valid) {
    verdictBadge.className = "badge bg-success font-monospace";
    verdictBadge.textContent = "DUAL-VALID CONFLICT CONFIRMED";
  } else {
    verdictBadge.className = "badge bg-warning text-dark font-monospace";
    verdictBadge.textContent = "PARTIAL VALIDITY / SUSPICIOUS";
  }

  // Hex Previews
  document.getElementById("crafterHexHead").textContent = data.hex_head;
  document.getElementById("crafterHexTail").textContent = data.hex_tail || "(Empty or file under 128 bytes)";

  // Download Link
  document.getElementById("crafterDownloadBtn").href = data.download_url;
}

async function sendBuiltToTestbed() {
  if (!activeBuiltFilename) return;

  // Switch to testbed tab
  const testbedTabBtn = document.getElementById("tab-testbed-btn");
  if (testbedTabBtn) {
    bootstrap.Tab.getOrCreateInstance(testbedTabBtn).show();
  }

  // Auto-detect tier
  let tier = "1";
  if (activeBuiltFilename.includes("php")) tier = "1";
  else if (activeBuiltFilename.includes("xss") || activeBuiltFilename.includes("html")) tier = "2";
  else if (activeBuiltFilename.includes("slip") || activeBuiltFilename.includes("zip")) tier = "2";

  const selTier = document.getElementById("testbedTierSelect");
  if (selTier) selTier.value = tier;

  // Set filename
  const tbInput = document.getElementById("testbedCustomFilename");
  if (tbInput) tbInput.value = activeBuiltFilename;

  // Physically attach the file into testbed file input & activate staged card
  if (typeof attachFileToTestbed === "function") {
    await attachFileToTestbed(activeBuiltFilename, tier);
  }
}
