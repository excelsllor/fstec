# Trivy-скан production-образов, 2026-11-16

Инструмент: Trivy 0.76.2, БД обновлена. Severity: HIGH, CRITICAL.

## Команда

```bash
/home/raport/sec-tools/trivy image --scanners vuln --severity HIGH,CRITICAL \
  --format json --output /home/raport/sec-tools/<image>.json --no-progress <image>
```

## Результаты

| Образ | CRITICAL | HIGH | Комментарий |
|---|---:|---:|---|
| services-api-gateway | 0 | 5 | Python FP нижнего слоя; pip-audit 0 |
| services-security-service | 0 | 5 | то же |
| services-reporting-service | 0 | 5 | то же |
| services-llm-service | 0 | 5 | то же |
| services-audit-service | 0 | 5 | то же |
| services-ingest-service | 0 | 5 | OCR сохранён; Python FP |
| services-nginx | 0 | 0 | — |
| fstec-postgres-hardened | 0 | 0 | 16.15-alpine + apk upgrade + gosu Go 1.27.3 |
| fstec-nginx-hardened | 0 | 0 | 1.29.8-alpine + apk upgrade |
| fstec-kafka412-patched3 | 0 | 0 | apache/kafka 4.1.2 + обновлённые JAR |
| redis:7.4.11-alpine | 0 | 0 | — |

## Фактические Python-пакеты

В запущенных сервисных контейнерах:

```text
msgpack 1.2.3
urllib3 2.8.0
setuptools 84.2.1
```

`pip-audit -r services/requirements.txt`: **53 зависимости, 0 уязвимостей**. Пять HIGH в Trivy относятся к метаданным нижнего слоя/`pip` vendor и не соответствуют runtime-пакетам.

## Kafka

JAR-обновления: Jackson core/databind 2.18.11; Jetty core 12.0.36; lz4-java 1.11.4; snappy-java 1.1.10.9; plexus-utils 3.6.1; jline 3.30.15. Брокер запущен с сохранённым SASL_SSL/PLAIN и томом `services_kafka41_data`; топики читаются. Trivy: 0/0.

## Ingest

Ubuntu 24.04 с сохранёнными `tesseract`, `poppler`, `pymupdf`, `pytesseract`; OCR-функциональность не уменьшена. `libxml2` CVE-2026-6653 в runtime больше не обнаруживается; CRITICAL 0.
