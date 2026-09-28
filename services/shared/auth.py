"""JWT-аутентификация для сервисов (общая для всех микросервисов)."""
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from shared.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    BOOTSTRAP_FULL_NAME,
    BOOTSTRAP_PASSWORD,
    BOOTSTRAP_USERNAME,
    DATA_DIR,
    JWT_AUDIENCE,
    MIN_PASSWORD_LENGTH,
    SECRET_KEY,
)
from shared.db import get_db
from shared.models import BootstrapSecret, User

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    pw = plain.encode("utf-8")[:72]
    try:
        return bcrypt.checkpw(pw, hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"iat": now, "aud": JWT_AUDIENCE, "exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=JWT_AUDIENCE)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось проверить учётные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Требуются права администратора")
    return user


def ensure_bootstrap(db: Session) -> Optional[str]:
    """Создаёт администратора при первом запуске; возвращает одноразовый пароль.

    Пароль берётся из FSTEC_BOOTSTRAP_PASSWORD, если задан (тогда в лог ничего не пишется);
    иначе генерируется и сохраняется в файл DATA_DIR/bootstrap_password.txt с правами 0600.
    Сам пароль в лог НЕ попадает.
    """
    if db.query(User).filter(User.username == BOOTSTRAP_USERNAME).first():
        return None
    from_env = bool(BOOTSTRAP_PASSWORD)
    password = BOOTSTRAP_PASSWORD or secrets.token_urlsafe(12)
    if len(password) < MIN_PASSWORD_LENGTH:
        password = secrets.token_urlsafe(14)
    db.add(User(
        username=BOOTSTRAP_USERNAME,
        password_hash=hash_password(password),
        role="admin",
        full_name=BOOTSTRAP_FULL_NAME,
        is_active=True,
    ))
    db.add(BootstrapSecret(username=BOOTSTRAP_USERNAME, secret=hash_password(password), used=False))
    db.commit()
    if from_env:
        logger.warning(
            "Bootstrap admin '%s' создан; пароль взят из FSTEC_BOOTSTRAP_PASSWORD.",
            BOOTSTRAP_USERNAME)
    else:
        try:
            secret_path = Path(DATA_DIR) / "bootstrap_password.txt"
            secret_path.write_text(password, encoding="utf-8")
            os.chmod(secret_path, 0o600)
            logger.warning(
                "Bootstrap admin '%s' создан; одноразовый пароль записан в %s "
                "(прочитайте и удалите файл после первого входа).",
                BOOTSTRAP_USERNAME, secret_path)
        except OSError as e:
            logger.error("Bootstrap: не удалось сохранить пароль в файл: %s", e)
    return password


def mark_bootstrap_used(db: Session) -> None:
    """Помечает bootstrap-секрет использованным после первого успешного входа."""
    rows = db.query(BootstrapSecret).filter(
        BootstrapSecret.username == BOOTSTRAP_USERNAME,
        BootstrapSecret.used.is_(False),
    ).all()
    for row in rows:
        row.used = True
    if rows:
        db.commit()


def needs_setup(db: Session) -> bool:
    """True, пока bootstrap-администратор ни разу не вошёл в систему."""
    return db.query(BootstrapSecret).filter(
        BootstrapSecret.username == BOOTSTRAP_USERNAME,
        BootstrapSecret.used.is_(False),
    ).count() > 0