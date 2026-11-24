import os
import glob
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / "uploads").mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Local S3 Mock Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/minio/health/live")
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=Response)
def list_buckets():
    """boto3 s3.list_buckets() response."""
    buckets = [d.name for d in DATA_DIR.iterdir() if d.is_dir()]
    if not buckets:
        buckets = ["uploads"]

    xml_buckets = "".join(
        f"<Bucket><Name>{b}</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>"
        for b in buckets
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Buckets>{xml_buckets}</Buckets>
</ListAllMyBucketsResult>"""
    return Response(content=xml, media_type="application/xml")


@app.api_route("/{bucket}", methods=["GET", "PUT", "DELETE"])
async def bucket_operations(bucket: str, request: Request):
    bucket_dir = DATA_DIR / bucket

    if request.method == "PUT":
        bucket_dir.mkdir(parents=True, exist_ok=True)
        return Response(status_code=200)

    if request.method == "GET":
        # Handle list_objects_v2 or list_objects
        files = []
        if bucket_dir.exists():
            for f in bucket_dir.glob("**/*"):
                if f.is_file():
                    rel = f.relative_to(bucket_dir).as_posix()
                    files.append((rel, f.stat().st_size, datetime.fromtimestamp(f.stat().st_mtime).isoformat() + "Z"))

        xml_contents = "".join(
            f"""<Contents>
                <Key>{k}</Key>
                <LastModified>{m}</LastModified>
                <ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>
                <Size>{s}</Size>
                <StorageClass>STANDARD</StorageClass>
            </Contents>"""
            for k, s, m in files
        )

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>{bucket}</Name>
    <Prefix></Prefix>
    <KeyCount>{len(files)}</KeyCount>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    {xml_contents}
</ListBucketResult>"""
        return Response(content=xml, media_type="application/xml")

    if request.method == "DELETE":
        return Response(status_code=204)


@app.api_route("/{bucket}/{key:path}", methods=["GET", "PUT", "HEAD", "DELETE"])
async def object_operations(bucket: str, key: str, request: Request):
    bucket_dir = DATA_DIR / bucket
    bucket_dir.mkdir(parents=True, exist_ok=True)
    file_path = bucket_dir / key

    if request.method == "PUT":
        file_path.parent.mkdir(parents=True, exist_ok=True)
        body = await request.body()
        file_path.write_bytes(body)
        print(f"[S3 MOCK] Stored object: {bucket}/{key} ({len(body)} bytes)")
        return Response(status_code=200, headers={"ETag": '"upload-success"'})

    if request.method in ("GET", "HEAD"):
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="NoSuchKey")

        data = file_path.read_bytes()
        # VULNERABILITY: Deliberately do NOT set 'X-Content-Type-Options: nosniff'
        # Deliberately do NOT set 'Content-Disposition: attachment'
        # Detect simple content type or default to image/png
        ctype = "image/png" if key.endswith(".png") else "image/jpeg" if key.endswith((".jpg", ".jpeg")) else "application/octet-stream"
        
        return Response(
            content=data if request.method == "GET" else b"",
            media_type=ctype,
            headers={
                "Content-Length": str(len(data)),
                "Access-Control-Allow-Origin": "*",
                # Note: No nosniff header intentionally
            }
        )

    if request.method == "DELETE":
        if file_path.exists():
            file_path.unlink()
        return Response(status_code=204)
