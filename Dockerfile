FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates tesseract-ocr tesseract-ocr-chi-sim \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium \
    && playwright install-deps chromium || true

COPY . .

RUN mkdir -p /app/reports /app/data && chmod +x /app/scripts/*.sh /app/cli.py || true

ENV DATA_DIR=/app/data \
    REPORTS_DIR=/app/reports \
    DATABASE_PATH=/app/data/xinru.db \
    PYTHONUNBUFFERED=1 \
    EXAM_MODE=1 \
    XINRU_UNATTENDED=1 \
    XINRU_WORKERS=2 \
    XINRU_LLM_MAX_RETRIES=5

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
