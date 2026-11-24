"""
Unit & Integration Tests for AppendStrategy
"""

import io
import zipfile
from pathlib import Path
from PIL import Image

from PolyMorph.core.constructor import Constructor
from PolyMorph.core.format_registry import FormatRegistry


def test_append_jpeg_zip(tmp_path: Path):
    host_path = tmp_path / "host.jpg"
    img = Image.new("RGB", (32, 32), color="red")
    img.save(host_path, format="JPEG")

    payload_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(payload_path, "w") as zf:
        zf.writestr("test.txt", b"APPEND_TEST")

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="jpeg",
        fmt_b="zip",
        force_strategy="append",
    )

    assert res.success is True
    assert res.strategy == "append"
    assert res.both_valid is True

    # Validate zip extraction
    with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
        assert zf.read("test.txt") == b"APPEND_TEST"


def test_append_png_zip(tmp_path: Path):
    host_path = tmp_path / "host.png"
    img = Image.new("RGB", (32, 32), color="blue")
    img.save(host_path, format="PNG")

    payload_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(payload_path, "w") as zf:
        zf.writestr("test.txt", b"APPEND_PNG_TEST")

    res = Constructor.build(
        file_a=host_path,
        file_b=payload_path,
        fmt_a="png",
        fmt_b="zip",
        force_strategy="append",
    )

    assert res.success is True
    assert res.strategy == "append"
    assert res.both_valid is True
