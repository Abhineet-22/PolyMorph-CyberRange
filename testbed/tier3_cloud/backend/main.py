"""
INTENTIONALLY VULNERABLE: Academic Research Lab
Tier 3 Cloud-Native testbed — S3 + FastAPI
Demonstrates: pre-signed URL bypass, parser differential, MIME confusion

WARNING: This code contains deliberate security vulnerabilities for
educational/research purposes. DO NOT deploy to any real environment.
"""
import os
import io
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import boto3
from botocore.client import Config
import magic  # python-magic for MIME detection

app = FastAPI(title="Tier 3 Cloud-Native Testbed", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
MINIO_PUBLIC_ENDPOINT = os.getenv("MINIO_PUBLIC_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
BUCKET_NAME = "uploads"
EXTRACT_DIR = "/tmp/polymorph_extracted"


def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


@app.on_event("startup")
def create_bucket_on_startup():
    """Create the uploads bucket on startup if it doesn't exist."""
    for attempt in range(15):
        try:
            s3 = get_s3_client()
            existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            if BUCKET_NAME not in existing:
                s3.create_bucket(Bucket=BUCKET_NAME)
                print(f"[startup] Created bucket '{BUCKET_NAME}'")
            else:
                print(f"[startup] Bucket '{BUCKET_NAME}' already exists")
            return
        except Exception as e:
            print(f"[startup] Storage not ready yet (attempt {attempt+1}/15): {e}")
            time.sleep(2)
    print("[startup] WARNING: Storage connection timeout")


@app.get("/health")
def health():
    return {"status": "ok", "tier": "cloud-native"}


@app.get("/get-upload-url")
def get_upload_url(filename: str, content_type: str = "image/png"):
    """
    VULNERABILITY: Returns a pre-signed URL for direct client upload.
    The client can use this URL to upload ANY file directly to S3 storage,
    completely bypassing all server-side validation.
    The content_type parameter is user-controlled and not validated.
    """
    s3 = get_s3_client()
    try:
        url = s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": BUCKET_NAME,
                "Key": filename,
                "ContentType": content_type,
            },
            ExpiresIn=300,
        )
        if "http://minio:9000" in url:
            url = url.replace("http://minio:9000", MINIO_PUBLIC_ENDPOINT)
        return {"upload_url": url, "filename": filename, "bucket": BUCKET_NAME}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/files")
def list_files():
    """List all uploaded files."""
    s3 = get_s3_client()
    try:
        resp = s3.list_objects_v2(Bucket=BUCKET_NAME)
        files = []
        for obj in resp.get("Contents", []):
            # VULNERABILITY: Public URL served without Content-Disposition: attachment
            # Browser will sniff content and may execute HTML payload
            public_url = f"http://localhost:9000/{BUCKET_NAME}/{obj['Key']}"
            files.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "url": public_url
            })
        return files
    except Exception as e:
        return []


@app.post("/validate-upload")
def validate_upload(filename: str):
    """
    VULNERABILITY: Parser differential between python-magic and zipfile.
    python-magic checks magic bytes (image passes).
    zipfile.ZipFile reads from EOCD at end (ZIP payload inside image also parsed).
    """
    import zipfile
    s3 = get_s3_client()
    try:
        obj = s3.get_object(Bucket=BUCKET_NAME, Key=filename)
        data = obj["Body"].read()

        # Check 1: python-magic detects image (passes for polyglot with image header)
        mime = magic.from_buffer(data[:2048], mime=True)
        result = {
            "filename": filename,
            "magic_mime": mime,
            "magic_pass": mime.startswith("image/"),
        }

        # Check 2: Try to parse as ZIP (VULNERABILITY: dual-consumer differential)
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            entries = zf.namelist()
            result["zip_detected"] = True
            result["zip_entries"] = entries
            result["differential_gap"] = "File passes image validation but also contains ZIP payload!"

            # VULNERABILITY: Extract ZIP entries without path sanitization (Zip-Slip)
            extract_dir = "/tmp/polymorph_extracted"
            os.makedirs(extract_dir, exist_ok=True)
            for entry in entries:
                extract_path = os.path.join(extract_dir, entry)
                print(f"[WORKER] Extracting: {entry} -> {extract_path}")
                with zf.open(entry) as src, open(extract_path, 'wb') as dst:
                    dst.write(src.read())
            result["extracted_to"] = extract_dir
        except zipfile.BadZipFile:
            result["zip_detected"] = False

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/extracted")
def list_extracted():
    """List all files extracted by the background worker."""
    if not os.path.exists(EXTRACT_DIR):
        return {"files": []}
    files = []
    for root, _, filenames in os.walk(EXTRACT_DIR):
        for fn in filenames:
            full_p = os.path.join(root, fn)
            rel_p = os.path.relpath(full_p, EXTRACT_DIR)
            content_preview = ""
            try:
                with open(full_p, "r", encoding="utf-8", errors="replace") as f:
                    content_preview = f.read(500)
            except Exception:
                pass
            files.append({
                "name": rel_p,
                "size": os.path.getsize(full_p),
                "preview": content_preview,
            })
    return {"files": files}


@app.post("/clear")
def clear_all():
    """Clear all uploaded objects in S3 and all extracted files."""
    cleared = {"s3_objects": 0, "extracted_files": 0}
    # Clear S3 bucket
    try:
        s3 = get_s3_client()
        resp = s3.list_objects_v2(Bucket=BUCKET_NAME)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=BUCKET_NAME, Key=obj["Key"])
            cleared["s3_objects"] += 1
    except Exception as e:
        print(f"[CLEAR] Error clearing S3: {e}")

    # Clear extracted dir
    if os.path.exists(EXTRACT_DIR):
        import shutil
        for item in os.listdir(EXTRACT_DIR):
            p = os.path.join(EXTRACT_DIR, item)
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p)
                else:
                    os.unlink(p)
                cleared["extracted_files"] += 1
            except Exception as e:
                print(f"[CLEAR] Error removing {p}: {e}")

    return {"status": "ok", "cleared": cleared}
