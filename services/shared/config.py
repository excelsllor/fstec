import os
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
_DATA = Path(os.environ.get("FSTEC_DATA_DIR", _BASE / "data"))

DATA_DIR = _DATA
UPLOAD_DIR = Path(os.environ.get("FSTEC_UPLOAD_DIR", DATA_DIR / "uploads"))
REPORT_DIR = Path(os.environ.get("FSTEC_REPORT_DIR", DATA_DIR / "reports"))
RAW_DIR = Path(os.environ.get("FSTEC_RAW_DIR", DATA_DIR / "raw"))
DB_PATH = DATA_DIR / "fstec_services.db"

for d in (UPLOAD_DIR, REPORT_DIR, RAW_DIR, DATA_DIR):
    d.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")

# Событийная шина: memory (тесты/один процесс) | sqlite (локальный мульти-процесс) | kafka (prod)
EVENT_BUS = os.environ.get("FSTEC_EVENT_BUS", "memory").lower()
BUS_POLL_S = float(os.environ.get("FSTEC_BUS_POLL_S", "0.25"))

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Auth
SECRET_KEY = os.environ.get("FSTEC_SECRET_KEY", "dev-insecure-change-me")
ALGORITHM = "HS256"
JWT_AUDIENCE = "fstec-service"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("FSTEC_TOKEN_MINUTES", "120"))


def _warn_insecure_secret() -> None:
    import warnings
    warnings.warn(
        "FSTEC_SECRET_KEY не задан — используется небезопасный dev-дефолт. "
        "Обязательно задайте секрет на боевом сервере!",
        RuntimeWarning, stacklevel=2)


if SECRET_KEY == "dev-insecure-change-me":
    _warn_insecure_secret()
BOOTSTRAP_USERNAME = "admin"
BOOTSTRAP_FULL_NAME = "Администратор"
MIN_PASSWORD_LENGTH = 6

# Загрузка (ТЗ 2.1)
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".odt", ".xlsx", ".rtf", ".txt"}
MAX_FILE_SIZE = 20 * 1024 * 1024          # ТЗ 2.1: 20 МБ
MAX_FILES_PER_BATCH = 10                  # ТЗ 2.1: до 10 файлов

# OCR (ТЗ 2.2)
OCR_ENABLED = os.environ.get("FSTEC_OCR_ENABLED", "false").lower() in ("1", "true", "yes")
OCR_LANG = os.environ.get("FSTEC_OCR_LANG", "rus+eng")
OCR_MIN_TEXT = int(os.environ.get("FSTEC_OCR_MIN_TEXT", "20"))
# Провайдер: auto (paddle → tesseract) | paddle | tesseract
OCR_ENGINE = os.environ.get("FSTEC_OCR_ENGINE", "auto").lower()
# Устройство распознавания: gpu (CUDA) | cpu (в dev и <=4 ГБ видеопамяти)
OCR_DEVICE = os.environ.get("FSTEC_OCR_DEVICE", "cpu").lower()
OCR_GPU_IDS = [int(x) for x in os.environ.get("FSTEC_OCR_GPU_IDS", "0").split(",") if x.strip().isdigit()]

# LLM (ТЗ 2.3)
LLM_PROVIDER = os.environ.get("FSTEC_LLM_PROVIDER", "heuristic")  # heuristic | vllm
VLLM_BASE_URL = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
VLLM_MODEL = os.environ.get("VLLM_MODEL", "Qwen3-14B-Instruct-Q4")
LLM_TIMEOUT_S = float(os.environ.get("FSTEC_LLM_TIMEOUT_S", "10"))
VLLM_MAX_TOKENS = int(os.environ.get("FSTEC_VLLM_MAX_TOKENS", "900"))
VLLM_TEMPERATURE = float(os.environ.get("FSTEC_VLLM_TEMPERATURE", "0.1"))
VLLM_TOP_P = float(os.environ.get("FSTEC_VLLM_TOP_P", "0.9"))
# Контекст llama-server -c 16384: на ЛЕВЫЙ промпт (после _fit_context) остаётся
# 16384 - VLLM_MAX_TOKENS = 15484 токенов — достаточно для писем целиком (макс ~12665).
CHUNK_MAX_TOKENS = int(os.environ.get("FSTEC_CHUNK_MAX_TOKENS", "15400"))
SUMMARY_MAX_CHARS = 500

# RuBERT-классификация (быстрый предиктор категорий, GPU под vLLM)
# deepvk/USER2-base — RuModernBERT (8192 токенов контекста) как замена ruBERT (512).
# RUBERT_MAX_TOKENS=2048 — измеренный оптимум: полный 8192 разбавляет mean-pooling
# длинными блок-списками и в 6 раз медленнее (11/12 на обоих, 2.0с против 12.7с/письмо).
RUBERT_MODEL = os.environ.get("FSTEC_RUBERT_MODEL", "deepvk/USER2-base")
RUBERT_DEVICE = os.environ.get("FSTEC_RUBERT_DEVICE", "cpu").lower()
RUBERT_CONFIDENCE = float(os.environ.get("FSTEC_RUBERT_CONFIDENCE", "0.35"))
RUBERT_MAX_TOKENS = int(os.environ.get("FSTEC_RUBERT_MAX_TOKENS", "2048"))

# Security (ТЗ 2.4)
SECURITY_MODE = os.environ.get("FSTEC_SECURITY_MODE", "live")  # mock (оффлайн/dev) | live (внешние БД)
SECURITY_RETRY_MAX = int(os.environ.get("FSTEC_SECURITY_RETRY_MAX", "3"))
SECURITY_CACHE_TTL_S = int(os.environ.get("FSTEC_SECURITY_CACHE_TTL_S", str(24 * 60 * 60)))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_API_BASE = os.environ.get("NVD_API_BASE", "https://services.nvd.nist.gov")
BDU_API_BASE = os.environ.get("BDU_API_BASE", "https://bdu.fstec.ru")
# Включать fallback с verify=False при сбое TLS у BDU (только для dev/тест-стендов; в проде оставить 0)
BDU_TLS_INSECURE_FALLBACK = os.environ.get("FSTEC_BDU_INSECURE_FALLBACK", "0") == "1"
# CMDB Заказчика (Приложение 8): провайдер mock (dev, тот же протокол) | rest
CMDB_PROVIDER = os.environ.get("CMDB_PROVIDER", "mock")
CMDB_ENDPOINT = os.environ.get("CMDB_ENDPOINT", "http://localhost:9000/api/inventory/software")
CMDB_AUTH_TYPE = os.environ.get("CMDB_AUTH_TYPE", "none")  # none | bearer | basic
CMDB_TOKEN = os.environ.get("CMDB_TOKEN", "")
CMDB_TIMEOUT_S = float(os.environ.get("CMDB_TIMEOUT_S", "5"))

# Порт gateway
GATEWAY_PORT = int(os.environ.get("FSTEC_GATEWAY_PORT", "8666"))

# Отчётность (ТЗ 2.5)
ORG_NAME = os.environ.get("FSTEC_ORG_NAME", "Правительства Липецкой области")