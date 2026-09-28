# Образ для всех микросервисов; команда запуска задаётся в docker-compose.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        poppler-utils tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng \
        libgl1 libglib2.0-0 libsm6 libxext6 libgomp1 \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# PaddleOCR (GPU) — только для ingest-service (WITH_OCR=true); тянет CUDA-колёса, поэтому опционально.
ARG WITH_OCR=false
COPY requirements-ocr.txt .
RUN if [ "$WITH_OCR" = "true" ]; then pip install --no-cache-dir -r requirements-ocr.txt; fi

COPY shared ./shared
COPY data/generator ./data/generator
COPY .env.example ./

ARG SERVICE
COPY ${SERVICE} ./${SERVICE}

# Непривилегированный пользователь; каталоги данных готовим заранее (named volume
# наследует владельца при первой инициализации).
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data/uploads /app/data/reports /app/data/raw /app/data/registry \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import shared" || exit 1

CMD ["python", "-c", "import shared; print('use compose command')"]
