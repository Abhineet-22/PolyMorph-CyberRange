import sys
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from studio.backend.main import app

client = TestClient(app)

def test_health_check():
    """Verify system health endpoint returns 200 and expected metadata."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["app"] == "PolyMorph Studio"
    assert "recon" in data["tabs"]
    assert "crafter" in data["tabs"]
    assert "testbed" in data["tabs"]

def test_static_index_serving():
    """Verify frontend index.html is served at root."""
    res = client.get("/")
    assert res.status_code == 200
    assert "PolyMorph" in res.text
    assert "CYBER RANGE" in res.text.upper()

def test_crafter_formats_list():
    """Verify crafter formats endpoint returns registered format specifications."""
    res = client.get("/api/crafter/formats")
    assert res.status_code == 200
    data = res.json()
    assert "formats" in data
    format_names = [f["name"] for f in data["formats"]]
    for expected in ["png", "zip", "jpeg", "html", "pdf", "docx"]:
        assert expected in format_names

def test_crafter_pair_info():
    """Verify crafter pair info analyzes format pair compatibility."""
    res = client.get("/api/crafter/info?fmt_a=png&fmt_b=zip")
    assert res.status_code == 200
    data = res.json()
    assert data["fmt_a"] == "png"
    assert data["fmt_b"] == "zip"
    assert "analysis" in data
    assert len(data["analysis"]) > 0

def test_crafter_samples_list():
    """Verify crafter lists sample files in project root."""
    res = client.get("/api/crafter/samples")
    assert res.status_code == 200
    data = res.json()
    assert "samples" in data
    filenames = [s["filename"] for s in data["samples"]]
    assert "sample.png" in filenames or "payload.zip" in filenames

def test_crafter_build_polyglot():
    """Verify in-process polyglot synthesis via Constructor.build()."""
    # Build PNG + ZIP using project sample files
    res = client.post(
        "/api/crafter/build",
        data={
            "fmt_a": "png",
            "fmt_b": "zip",
            "strategy": "auto",
            "sample_a": "sample.png",
            "sample_b": "payload.zip",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["fmt_a"] == "png"
    assert data["fmt_b"] == "zip"
    assert data["strategy"] == "append"
    assert data["both_valid"] is True
    assert "hex_head" in data
    assert "hex_tail" in data
    assert data["download_url"].startswith("/api/crafter/download/")

    # Test downloading the created polyglot
    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 200
    assert len(dl_res.content) == data["size_bytes"]

def test_download_root_sample():
    """Verify crafter download endpoint falls back to project root samples."""
    res = client.get("/api/crafter/download/shell.jpg")
    assert res.status_code == 200
    assert len(res.content) > 0

def test_testbed_status_endpoint():
    """Verify testbed status probing returns status objects for all 3 tiers."""
    res = client.get("/api/testbed/status")
    assert res.status_code == 200
    data = res.json()
    assert "tiers" in data
    assert len(data["tiers"]) == 3
    tiers = {t["tier"]: t for t in data["tiers"]}
    assert 1 in tiers
    assert 2 in tiers
    assert 3 in tiers
    assert "Legacy LAMP" in tiers[1]["name"]
    assert "Modern MERN" in tiers[2]["name"]
    assert "Cloud-Native" in tiers[3]["name"]

def test_testbed_extracted_endpoint():
    """Verify aggregated extracted worker artifacts endpoint."""
    res = client.get("/api/testbed/extracted")
    assert res.status_code == 200
    data = res.json()
    assert "tier2" in data
    assert "tier3" in data


def test_recon_scan_endpoint_includes_content_surfaces():
    """Verify recon scan API returns content_surfaces in response payload."""
    from unittest.mock import patch
    from PolyMorph.probe.target_scanner import ScanReport, ContentSurface

    mock_report = ScanReport(
        target="http://test.local",
        scan_time_utc="2026-11-24T00:00:00Z",
        duration_seconds=0.5,
        pages_crawled=1,
        tech_summary={},
        tech_evidence=[],
        upload_endpoints=[],
        content_surfaces=[
            ContentSurface(
                category="doc_processing",
                label="Document Processing Pipeline (pdfminer.six)",
                url="http://test.local",
                evidence="pdfminer",
                risk_note="CVE-2025-64512",
                severity="high",
            )
        ],
        security_gaps=[],
        recommendations=[],
        server_info={},
        crawled_pages=[],
        exposed_paths=[],
    )
    with patch("studio.backend.routes.recon.TargetScanner.scan", return_value=mock_report):
        res = client.post("/api/recon/scan", json={"url": "http://test.local", "depth": 1, "pages": 1})
        assert res.status_code == 200
        data = res.json()
        assert "content_surfaces" in data
        assert len(data["content_surfaces"]) == 1
        assert data["content_surfaces"][0]["category"] == "doc_processing"

