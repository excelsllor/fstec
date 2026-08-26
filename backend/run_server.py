"""Точка входа для собранного (PyInstaller) бэкенда.

Запускает uvicorn на 127.0.0.1:8765. Все данные (БД, uploads, secret.key, логи)
по умолчанию хранятся в %LOCALAPPDATA%\\fstec-service, чтобы установка была
полностью офлайн и данные переживали перезапуск/обновление приложения.
"""
import os
import sys
import logging
from pathlib import Path


def _default_data_dir() -> str:
    appdata = os.environ.get("LOCALAPPDATA")
    if not appdata:
        appdata = os.environ.get("APPDATA") or str(Path.home())
    return str(Path(appdata) / "fstec-service")


def main():
    os.environ.setdefault("FSTEC_DATA_DIR", _default_data_dir())
    os.environ.setdefault("FSTEC_DISABLE_DOCS", "1")

    from app.main import app as fastapi_app
    from app.config import HOST, PORT, DATA_DIR
    import uvicorn

    log_dir = DATA_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "backend.log"

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"},
            "access": {"format": "%(asctime)s %(levelname)s %(message)s"},
        },
        "handlers": {
            "default": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": str(log_file),
                "maxBytes": 5 * 1024 * 1024,
                "backupCount": 2,
                "encoding": "utf-8",
                "formatter": "default",
            },
            "stderr": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "formatter": "default",
            },
            "access": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": str(log_file),
                "maxBytes": 5 * 1024 * 1024,
                "backupCount": 2,
                "encoding": "utf-8",
                "formatter": "access",
            },
        },
        "root": {
            "handlers": ["default", "stderr"],
            "level": "WARNING",
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"level": "INFO"},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
        },
    }

    uvicorn.run(
        fastapi_app,
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True,
        log_config=log_config,
    )


if __name__ == "__main__":
    main()
