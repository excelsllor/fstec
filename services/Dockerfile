FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app

ARG SERVICE=api_gateway
ARG WITH_OCR=false

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates python3.12 python3.12-venv python3-pip \
    && if [ "$SERVICE" = "ingest_service" ]; then \
         apt-get install -y --no-install-recommends \
           poppler-utils tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng \
           libgl1 libglib2.0-0 libsm6 libxext6 libgomp1; \
         if [ "$WITH_OCR" = "true" ]; then \
           apt-get install -y --no-install-recommends libreoffice-writer; \
         fi; \
       fi \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN python3.12 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip==26.2.2

COPY requirements.txt .
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
RUN apt-get purge -y python3-pip python3-setuptools python3-urllib3 python3-msgpack 2>/dev/null || true; \
    apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

COPY requirements-ocr.txt .
RUN if [ "$WITH_OCR" = "true" ]; then /opt/venv/bin/pip install --no-cache-dir -r requirements-ocr.txt; fi

COPY shared ./shared
COPY data/generator ./data/generator
COPY .env.example ./

COPY ${SERVICE} ./${SERVICE}
COPY security_service ./security_service
COPY tools ./tools
COPY llm_service ./llm_service

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data/uploads /app/data/reports /app/data/raw /app/data/registry \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import shared" || exit 1

CMD ["python", "-c", "import shared; print('use compose command')"]
