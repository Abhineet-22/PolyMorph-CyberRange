"""
Unit & Integration Tests for InjectStrategy and Format Helpers
"""

import io
import struct
import zipfile
from pathlib import Path
import pytest
from PIL import Image

from PolyMorph.core.constructor import Constructor
from PolyMorph.core.format_registry import FormatRegistry, PolyStrategy
from PolyMorph.formats import jpeg as jpeg_fmt
from PolyMorph.formats import png as png_fmt
from PolyMorph.formats import gif as gif_fmt
from PolyMorph.formats import html as html_fmt
from PolyMorph.formats import zip_fmt


def test_jpeg_injection(tmp_path: Path):
    # Create test JPEG
    host_path = tmp_path / "host.jpg"
    img = Image.new("RGB", (32, 32), color="red")
    img.save(host_path, format="JPEG")

    # Create HTML payload
    payload_path = tmp_path / "payload.html"
    payload_path.write_text("<!DOCTYPE html><html><body><script>alert(1)</script></body></html>", encoding="utf-8")

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="jpeg",
        fmt_b="html",
        force_strategy="inject",
    )

    assert res.success is True
    assert res.strategy == "inject"
    assert res.both_valid is True
    assert res.validation_a.valid is True
    assert res.validation_b.valid is True

    # Verify comments can be extracted
    comments = jpeg_fmt.extract_comments(res.data)
    assert len(comments) > 0
    assert b"<script>alert(1)</script>" in comments[0]


def test_png_injection_with_crc(tmp_path: Path):
    # Create test PNG
    host_path = tmp_path / "host.png"
    img = Image.new("RGB", (32, 32), color="blue")
    img.save(host_path, format="PNG")

    # Create test ZIP payload
    payload_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(payload_path, "w") as zf:
        zf.writestr("test.txt", b"INJECT_CRC_TEST")

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="png",
        fmt_b="zip",
        force_strategy="inject",
    )

    assert res.success is True
    assert res.strategy == "inject"
    assert res.both_valid is True

    # Verify PNG chunk is readable and valid
    chunks = png_fmt.extract_chunks(res.data, b"tEXt")
    assert len(chunks) > 0
    assert b"Comment\x00" in chunks[0]

    # Verify ZIP extracts properly
    with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
        assert zf.read("test.txt") == b"INJECT_CRC_TEST"


def test_gif_injection(tmp_path: Path):
    # Create test GIF
    host_path = tmp_path / "host.gif"
    img = Image.new("RGB", (32, 32), color="green")
    img.save(host_path, format="GIF")

    # Create HTML payload
    payload_path = tmp_path / "payload.html"
    payload_path.write_text("<!DOCTYPE html><html><body><h1>GIF_INJECT</h1></body></html>", encoding="utf-8")

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="gif",
        fmt_b="html",
        force_strategy="inject",
    )

    assert res.success is True
    assert res.strategy == "inject"
    assert res.both_valid is True

    comments = gif_fmt.extract_comments(res.data)
    assert len(comments) > 0
    assert b"GIF_INJECT" in comments[0]


def test_html_host_injection(tmp_path: Path):
    host_path = tmp_path / "host.html"
    host_path.write_text("<!DOCTYPE html><html><head><title>Host</title></head><body>Hello</body></html>", encoding="utf-8")

    payload_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(payload_path, "w") as zf:
        zf.writestr("secret.txt", b"SECRET_IN_HTML")

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="html",
        fmt_b="zip",
        force_strategy="inject",
    )

    assert res.success is True
    assert res.strategy == "inject"
    assert res.both_valid is True

    # Verify ZIP extracts
    with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
        assert zf.read("secret.txt") == b"SECRET_IN_HTML"


def test_jpeg_payload_oversize_error(tmp_path: Path):
    host_path = tmp_path / "host.jpg"
    img = Image.new("RGB", (32, 32), color="red")
    img.save(host_path, format="JPEG")

    # Create dummy ZIP > 65533 bytes
    payload_path = tmp_path / "large.zip"
    with zipfile.ZipFile(payload_path, "w") as zf:
        zf.writestr("huge.bin", b"A" * 70000)

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="jpeg",
        fmt_b="zip",
        force_strategy="inject",
    )

    assert res.success is False
    assert "exceeds single JPEG COM" in res.error
