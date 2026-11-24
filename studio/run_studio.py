#!/usr/bin/env python3
"""
PolyMorph Studio — Unified Cyber Range & Workbench Launcher
Runs the PolyMorph Studio web application on host port 8888.
"""
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn

def main():
    print("=" * 72)
    print("  ⚡ PolyMorph Studio — Unified Cyber Range & Polyglot Workbench")
    print("  National Forensic Sciences University (NFSU), Gandhinagar")
    print("=" * 72)
    print("  • Host URL   : http://localhost:8888")
    print("  • API Docs   : http://localhost:8888/docs")
    print("  • Core Engine: Format Registry & Constructor (In-Process)")
    print("  • Range Hub  : Tier 1 (:8081), Tier 2 (:3001), Tier 3 (:8000)")
    print("=" * 72)
    print("[*] Launching uvicorn server on 0.0.0.0:8888 (Press Ctrl+C to stop)...")
    
    uvicorn.run(
        "studio.backend.main:app",
        host="0.0.0.0",
        port=8888,
        reload=True,
        reload_dirs=[str(PROJECT_ROOT / "studio"), str(PROJECT_ROOT / "PolyMorph")],
        log_level="info",
    )

if __name__ == "__main__":
    main()
