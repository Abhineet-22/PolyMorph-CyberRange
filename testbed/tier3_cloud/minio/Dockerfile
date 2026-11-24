FROM python:3.11-slim
WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn

COPY s3_server.py .
RUN mkdir -p /data/uploads

EXPOSE 9000
CMD ["uvicorn", "s3_server:app", "--host", "0.0.0.0", "--port", "9000"]
