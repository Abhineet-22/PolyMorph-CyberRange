#!/bin/sh
# Wait for MinIO to be ready, then create public bucket
sleep 5
mc alias set local http://minio:9000 minioadmin minioadmin
mc mb local/uploads --ignore-existing
mc anonymous set public local/uploads
echo "Bucket 'uploads' created and set to public"
