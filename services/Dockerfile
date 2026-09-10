# Образ для всех микросервисов; команда запуска задаётся в docker-compose.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        poppler-utils tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY .env.example ./

ARG SERVICE
COPY ${SERVICE} ./${SERVICE}

RUN mkdir -p /app/data/uploads /app/data/reports /app/data/raw

EXPOSE 8000

CMD ["python", "-c", "import shared; print('use compose command')"]