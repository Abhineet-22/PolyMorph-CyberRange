// PolyMorph Studio — Main Application Entry

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Testbed status when switching to testbed tab
  const testbedTabBtn = document.getElementById("tab-testbed-btn");

  if (testbedTabBtn) {
    testbedTabBtn.addEventListener("shown.bs.tab", () => {
      initTestbed();
    });
  }

  // Pre-initialize crafter format options in background on app load
  initCrafter();
});
