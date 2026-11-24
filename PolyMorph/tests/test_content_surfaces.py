"""Unit tests for content processing attack surface detection and polyglot recommendations.

Tests the extension of TargetScanner to detect attack surfaces beyond traditional
file upload forms (CVE-2025-64512 vector, MIME confusion, cloud storage, API ingestion,
and SVG DOM scripting surfaces — v2.4.0).
"""

from PolyMorph.probe.target_scanner import TargetScanner, ScanOptions, ContentSurface, ScanReport


def test_content_surface_dataclass():
    """Verify ContentSurface dataclass attributes and defaults."""
    s = ContentSurface(
        category="doc_processing",
        label="Document Processing Pipeline (pdfminer.six)",
        url="http://example.com/docs",
        evidence="indicator: pdfminer",
        risk_note="CVE-2025-64512 vector",
        severity="high",
    )
    assert s.category == "doc_processing"
    assert s.severity == "high"


def test_detect_content_surfaces_all_categories():
    """Verify that _detect_content_surfaces detects all 6 surface categories from HTML DOM."""
    scanner = TargetScanner(ScanOptions())

    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Processing Testbed</title></head>
    <body>
      <!-- 1. Media serving without nosniff -->
      <img src="/media/logo.png" alt="Logo">
      
      <!-- 2. Document processing pipeline (CVE-2025-64512 vector) -->
      <script src="/static/js/pdfminer.js"></script>

      <!-- 3. Content embedding without sandbox -->
      <iframe src="/embedded/frame"></iframe>

      <!-- 4. API ingestion -->
      <script>
        const fd = new FormData();
        fetch('/api/upload', { method: 'POST', body: fd });
      </script>

      <!-- 5. Cloud storage reference -->
      <a href="https://s3.amazonaws.com/company-assets/data.zip">S3 Bucket</a>

      <!-- 6. Download / serve route -->
      <a href="/download/export.csv">Download Data</a>
    </body>
    </html>
    """

    surfaces = scanner._detect_content_surfaces(
        html=html,
        page_url="http://target.local/portal",
        headers={"content-type": "text/html"},  # Missing nosniff
        origin="http://target.local",
    )

    categories = {s.category for s in surfaces}
    expected_categories = {
        "media_serving",
        "doc_processing",
        "content_embed",
        "api_ingestion",
        "cloud_storage",
        "download_serve",
    }
    assert expected_categories.issubset(categories)

    # Verify CVE reference attribution
    doc_surface = next(s for s in surfaces if s.category == "doc_processing")
    assert doc_surface.cve_ref == "CVE-2025-64512"
    media_surface = next(s for s in surfaces if s.category == "media_serving")
    assert "MIME Confusion" in media_surface.cve_ref


def test_detect_content_surfaces_from_headers():
    """Verify header-based surface detection on non-HTML responses."""
    scanner = TargetScanner(ScanOptions())

    # Inline file serving without Content-Disposition: attachment
    s1 = scanner._detect_content_surfaces_from_headers(
        url="http://target.local/files/whitepaper.pdf",
        headers={"content-type": "application/pdf"},
    )
    assert len(s1) == 1
    assert s1[0].category == "download_serve"
    assert s1[0].severity == "high"

    # API endpoint accepting multipart binary
    s2 = scanner._detect_content_surfaces_from_headers(
        url="http://target.local/api/v1/ingest",
        headers={"content-type": "multipart/form-data; boundary=xyz"},
    )
    assert len(s2) == 1
    assert s2[0].category == "api_ingestion"


def test_surface_polyglot_recommendations():
    """Verify that discovered content surfaces generate targeted polyglot recommendations."""
    scanner = TargetScanner(ScanOptions())

    surfaces = [
        ContentSurface(
            category="doc_processing",
            label="Document Processing Pipeline (pdfminer.six)",
            url="http://target.local/process",
            evidence="pdfminer indicator",
            risk_note="CVE-2025-64512 vector",
            severity="high",
        ),
        ContentSurface(
            category="media_serving",
            label="Inline Media Serving (no nosniff)",
            url="http://target.local/gallery",
            evidence="img tag",
            risk_note="MIME confusion",
            severity="high",
        ),
    ]

    recs = scanner._generate_recommendations(
        tech_summary={},
        security_gaps=[],
        upload_endpoints=[],
        content_surfaces=surfaces,
    )

    triggers = [r.trigger for r in recs]
    assert any("doc_processing" in t for t in triggers)
    assert any("media_serving" in t for t in triggers)

    doc_rec = next(r for r in recs if "doc_processing" in r.trigger)
    assert doc_rec.strategy == "append"
    assert doc_rec.payload_format == "zip"
    assert "CVE-2025-64512" in doc_rec.risk

    media_rec = next(r for r in recs if "media_serving" in r.trigger)
    assert media_rec.strategy == "inject"
    assert media_rec.payload_format == "html"


def test_source_sink_correlation_static_vs_active():
    """Verify that targets without upload vectors are classified as Latent/Supply-Chain."""
    scanner = TargetScanner(ScanOptions())

    html = """
    <html><body>
      <img src="/me.jpg" alt="Profile">
    </body></html>
    """

    # Static site (no upload forms, no ingress)
    latent_surfs = scanner._detect_content_surfaces(
        html=html,
        page_url="https://static.example.com",
        headers={"content-type": "text/html"},
        origin="https://static.example.com",
        has_ingress=False,
    )
    assert len(latent_surfs) == 1
    assert latent_surfs[0].exploitability == "latent"
    assert latent_surfs[0].severity == "medium"
    assert "Supply-Chain" in latent_surfs[0].label
    assert "https://static.example.com/me.jpg" in latent_surfs[0].endpoints

    # Active site (upload endpoints or API present)
    active_surfs = scanner._detect_content_surfaces(
        html=html,
        page_url="https://app.example.com",
        headers={"content-type": "text/html"},
        origin="https://app.example.com",
        has_ingress=True,
    )
    assert len(active_surfs) == 1
    assert active_surfs[0].exploitability == "active"
    assert active_surfs[0].severity == "high"
    assert "Active Delivery" in active_surfs[0].label


def test_client_side_parameter_reflection_detection():
    """Verify that client-side parameter parsing with DOM embedding sinks is flagged as active ingress."""
    scanner = TargetScanner(ScanOptions())

    html_with_preview = """
    <!DOCTYPE html>
    <html>
    <head><title>Portfolio</title></head>
    <body>
        <script>
            const params = new URLSearchParams(window.location.search);
            const previewUrl = params.get('preview') || params.get('view');
            if (previewUrl) {
                const obj = document.createElement('object');
                obj.data = previewUrl;
                document.body.appendChild(obj);
            }
        </script>
    </body>
    </html>
    """

    surfaces = scanner._detect_content_surfaces(
        html=html_with_preview,
        page_url="https://abhineetagrawal.netlify.app",
        headers={"content-type": "text/html"}, # no nosniff
        origin="https://abhineetagrawal.netlify.app",
        has_ingress=False,
    )

    param_surfs = [s for s in surfaces if s.category == "param_reflection"]
    assert len(param_surfs) == 1
    p = param_surfs[0]
    assert p.exploitability == "active"
    assert p.severity == "high"
    assert "https://abhineetagrawal.netlify.app?preview=" in p.endpoints
    assert "DOM Media/Object Viewer" in p.label

    # Verify recommendation synthesis
    recs = scanner._generate_recommendations(
        tech_summary={},
        security_gaps=[],
        upload_endpoints=[],
        content_surfaces=surfaces,
        target_url="https://abhineetagrawal.netlify.app",
    )
    rec_param = next((r for r in recs if "param_reflection" in r.trigger), None)
    assert rec_param is not None
    assert rec_param.strategy == "inject"
    assert rec_param.payload_format == "html"
    assert rec_param.exploitability == "active"


def test_svg_surface_detection():
    """Verify SVG inline element and upload forms are detected as svg_serving surface.

    SVG is an XML DOM format with native W3C <script> support (SVG spec §18.5).
    Unlike PNG/JPEG which are binary pixel matrices, SVG instantiates a full DOM
    when served as image/svg+xml, allowing script execution in the serving origin.
    This test validates that the recon module correctly identifies SVG attack surfaces
    and generates appropriate inject-strategy recommendations.
    """
    scanner = TargetScanner(ScanOptions())

    html_with_svg = """\
    <!DOCTYPE html>
    <html>
    <head><title>Gallery</title></head>
    <body>
        <!-- External SVG asset served via <object> without type= attribute -->
        <object data="/assets/logo.svg"></object>

        <!-- Inline SVG element in page source -->
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
          <path d="M3 6H21M3 12H21M3 18H21"/>
        </svg>

        <!-- Image upload form accepting any image (SVG capable) -->
        <form method="POST" action="/api/avatar" enctype="multipart/form-data">
          <input type="file" name="avatar" accept="image/*"/>
          <button type="submit">Upload Avatar</button>
        </form>
    </body>
    </html>
    """

    surfaces = scanner._detect_content_surfaces(
        html=html_with_svg,
        page_url="https://app.example.com/gallery",
        headers={"content-type": "text/html"},  # no CSP, no nosniff
        origin="https://app.example.com",
        has_ingress=True,
    )

    svg_surfs = [s for s in surfaces if s.category == "svg_serving"]
    assert len(svg_surfs) == 1, f"Expected 1 svg_serving surface, got {len(svg_surfs)}"

    s = svg_surfs[0]
    assert s.severity == "high", "SVG without CSP script-src:none should be high severity"
    assert s.exploitability == "active", "Upload form present — should be active, not latent"
    assert "SVG" in s.cve_ref, f"CWE reference should mention SVG, got: {s.cve_ref}"
    assert s.delivery_chain, "Delivery chain must be populated"

    # Verify recommendation is generated for svg_serving surface
    recs = scanner._generate_recommendations(
        tech_summary={},
        security_gaps=[],
        upload_endpoints=[],
        content_surfaces=svg_surfs,
        target_url="https://app.example.com/gallery",
    )
    rec_svg = next((r for r in recs if "svg" in r.trigger.lower()), None)
    assert rec_svg is not None, "No recommendation generated for svg_serving surface"
    assert rec_svg.strategy == "inject"
    assert rec_svg.payload_format == "html"


def test_svg_csp_severity_downgrade():
    """Verify SVG surface severity is downgraded to medium when CSP blocks scripts."""
    scanner = TargetScanner(ScanOptions())

    html_with_svg = """\
    <html><body>
      <svg xmlns="http://www.w3.org/2000/svg"><circle r="10" cx="12" cy="12"/></svg>
    </body></html>
    """

    # CSP with script-src 'none' — should block SVG script execution
    surfaces = scanner._detect_content_surfaces(
        html=html_with_svg,
        page_url="https://secure.example.com",
        headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; script-src 'none'",
        },
        origin="https://secure.example.com",
        has_ingress=False,
    )

    svg_surfs = [s for s in surfaces if s.category == "svg_serving"]
    assert len(svg_surfs) == 1

    # CSP with script-src 'none' should downgrade severity
    assert svg_surfs[0].severity == "medium", (
        f"CSP-protected SVG should be medium severity, got: {svg_surfs[0].severity}"
    )


