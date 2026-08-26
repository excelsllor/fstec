import os
import secrets
import stat
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("FSTEC_DATA_DIR")) if os.environ.get("FSTEC_DATA_DIR") else BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "fstec.db"

DATABASE_URL = f"sqlite:///{DB_PATH}"

ALGORITHM = "HS256"
JWT_AUDIENCE = "fstec-service"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 128

BOOTSTRAP_USERNAME = "admin"
BOOTSTRAP_FULL_NAME = "Администратор"

HOST = "127.0.0.1"
PORT = 8765

ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".odt", ".xlsx", ".xls"}

MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_TOTAL_SIZE = 100 * 1024 * 1024

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SECRET_FILE = DATA_DIR / "secret.key"


def _load_or_create_secret(path: Path) -> str:
    env_key = os.environ.get("FSTEC_SECRET_KEY")
    if env_key:
        return env_key
    try:
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        value = secrets.token_hex(32)
        path.write_text(value, encoding="utf-8")
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError as e:
            logger.error("Cannot set permissions on %s: %s — secret key may be world-readable", path, e)
        return value
    except OSError as e:
        logger.critical("Cannot read or write secret key at %s: %s — token verification will fail", path, e)
        raise SystemExit(1) from e


SECRET_KEY = _load_or_create_secret(SECRET_FILE)
