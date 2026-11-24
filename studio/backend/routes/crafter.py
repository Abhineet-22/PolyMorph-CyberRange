import sys
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PolyMorph.core.format_registry import FormatRegistry
from PolyMorph.core.constructor import Constructor

router = APIRouter(prefix="/api/crafter", tags=["crafter"])

STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def _format_hex_preview(data: bytes, limit: int = 128) -> str:
    """Return a formatted hex dump representation of the first bytes."""
    lines = []
    chunk = data[:limit]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{i:04x}  {hex_part:<48}  |{ascii_part}|")
    return "\n".join(lines)


@router.get("/formats")
def list_formats():
    """List all registered format contracts and their capabilities."""
    formats = []
    for name in FormatRegistry.all_names():
        spec = FormatRegistry.get(name)
        formats.append({
            "name": name,
            "extensions": list(spec.extensions),
            "mime_types": list(spec.mime_types),
            "append_tolerant": spec.append_tolerant,
            "prepend_tolerant": spec.prepend_tolerant,
            "max_prepend_bytes": spec.max_prepend_bytes,
            "scans_from_end": spec.scans_from_end,
            "has_comment_field": spec.has_comment_field,
            "comment_max_bytes": spec.comment_max_bytes,
            "validator": spec.validator or "native",
        })
    return {"formats": formats}


@router.get("/info")
def pair_info(fmt_a: str, fmt_b: str):
    """Analyze viable synthesis strategies for a format pair."""
    try:
        desc = FormatRegistry.describe_pair(fmt_a.lower(), fmt_b.lower())
        return {"fmt_a": fmt_a, "fmt_b": fmt_b, "analysis": desc}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/samples")
def list_sample_files():
    """List available sample files in the project root."""
    samples = []
    for ext in ("*.png", "*.jpeg", "*.jpg", "*.zip", "*.php", "*.html", "*.pdf", "*.svg"):
        for p in PROJECT_ROOT.glob(ext):
            samples.append({
                "filename": p.name,
                "size_bytes": p.stat().st_size,
                "extension": p.suffix.lower(),
            })
    return {"samples": samples}


@router.post("/build")
async def build_polyglot(
    fmt_a: str = Form(...),
    fmt_b: str = Form(...),
    strategy: Optional[str] = Form(None),
    sample_a: Optional[str] = Form(None),
    sample_b: Optional[str] = Form(None),
    file_a: Optional[UploadFile] = File(None),
    file_b: Optional[UploadFile] = File(None),
):
    """
    Synthesize a dual-format polyglot file using PolyMorph's Constructor.
    Accepts either uploaded files or pre-existing sample filenames from project root.
    """
    temp_dir = tempfile.mkdtemp(prefix="polymorph_build_")
    path_a = None
    path_b = None

    try:
        # Resolve File A (Host)
        if file_a and file_a.filename:
            path_a = Path(temp_dir) / file_a.filename
            with open(path_a, "wb") as f:
                shutil.copyfileobj(file_a.file, f)
        elif sample_a:
            src = PROJECT_ROOT / sample_a
            if not src.exists():
                src = PROJECT_ROOT / "files" / sample_a
            if not src.exists():
                raise HTTPException(status_code=400, detail=f"Sample A not found: {sample_a}")
            path_a = src
        else:
            raise HTTPException(status_code=400, detail="Host file (file_a or sample_a) required.")

        # Resolve File B (Payload)
        if file_b and file_b.filename:
            path_b = Path(temp_dir) / file_b.filename
            with open(path_b, "wb") as f:
                shutil.copyfileobj(file_b.file, f)
        elif sample_b:
            src = PROJECT_ROOT / sample_b
            if not src.exists():
                src = PROJECT_ROOT / "files" / sample_b
            if not src.exists():
                raise HTTPException(status_code=400, detail=f"Sample B not found: {sample_b}")
            path_b = src
        else:
            raise HTTPException(status_code=400, detail="Payload file (file_b or sample_b) required.")

        # Execute PolyMorph Synthesis Engine
        strat_param = strategy.lower() if strategy and strategy.lower() != "auto" else None
        result = Constructor.build(
            file_a=path_a,
            file_b=path_b,
            fmt_a=fmt_a.lower(),
            fmt_b=fmt_b.lower(),
            force_strategy=strat_param,
            skip_validation=False,
        )

        if not result.success:
            return {
                "success": False,
                "error": result.error,
                "fmt_a": fmt_a,
                "fmt_b": fmt_b,
            }

        # Save synthesized polyglot in storage dir
        out_filename = f"polyglot_{fmt_a.lower()}_{fmt_b.lower()}_{result.sha256[:8]}.{fmt_a.lower()}"
        out_path = STORAGE_DIR / out_filename
        out_path.write_bytes(result.data)

        # Build hex previews (head and tail)
        hex_head = _format_hex_preview(result.data, limit=128)
        hex_tail = _format_hex_preview(result.data[-128:], limit=128) if len(result.data) > 128 else ""

        return {
            "success": True,
            "filename": out_filename,
            "fmt_a": result.fmt_a,
            "fmt_b": result.fmt_b,
            "strategy": result.strategy,
            "size_bytes": result.size_bytes,
            "sha256": result.sha256,
            "notes": result.notes,
            "both_valid": result.both_valid,
            "validation_a": {
                "valid": result.validation_a.valid if result.validation_a else False,
                "detail": result.validation_a.detail if result.validation_a else "Not tested",
            },
            "validation_b": {
                "valid": result.validation_b.valid if result.validation_b else False,
                "detail": result.validation_b.detail if result.validation_b else "Not tested",
            },
            "hex_head": hex_head,
            "hex_tail": hex_tail,
            "download_url": f"/api/crafter/download/{out_filename}",
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("/download/{filename}")
def download_polyglot(filename: str):
    """Download a synthesized polyglot artifact."""
    fpath = STORAGE_DIR / filename
    if not fpath.exists() or not fpath.is_file():
        fpath = PROJECT_ROOT / filename
    if not fpath.exists() or not fpath.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(
        path=fpath,
        filename=filename,
        media_type="application/octet-stream"
    )
