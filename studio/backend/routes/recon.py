import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# Ensure PolyMorph is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PolyMorph.probe.target_scanner import TargetScanner, ScanOptions

router = APIRouter(prefix="/api/recon", tags=["recon"])


class ScanRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://localhost:8081"})
    depth: int = Field(default=2, ge=1, le=5)
    pages: int = Field(default=30, ge=1, le=100)
    timeout: int = Field(default=8, ge=2, le=30)
    probe_common: bool = Field(default=True)
    verify_tls: bool = Field(default=True, description="Enforce strict TLS validation using certifi CA bundle")


@router.post("/scan")
def run_recon_scan(req: ScanRequest):
    """Run an evidence-driven reconnaissance scan on the given URL."""
    try:
        opts = ScanOptions(
            max_depth=req.depth,
            max_pages=req.pages,
            timeout=req.timeout,
            probe_common_paths=req.probe_common,
            verify_tls=req.verify_tls,
        )
        scanner = TargetScanner(opts)
        report = scanner.scan(req.url)
        return report.as_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recon scan failed: {str(e)}")
