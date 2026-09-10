"""JWT-аутентификация для сервисов (общая для всех микросервисов)."""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from shared.config import (
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, JWT_AUDIENCE,
    BOOTSTRAP_USERNAME, BOOTSTRAP_FULL_NAME, MIN_PASSWORD_LENGTH,
)
from shared.db import get_db
from shared.models import User, BootstrapSecret

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
    """Создаёт администратора при первом запуске; возвращает одноразовый пароль."""
    if db.query(User).filter(User.username == BOOTSTRAP_USERNAME).first():
        return None
    password = secrets.token_urlsafe(12)
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
    logger.warning(
        "Bootstrap password for user '%s': %s — shown only once. "
        "Delete bootstrap_secrets rows after first login.",
        BOOTSTRAP_USERNAME, password,
    )
    return password


def needs_setup(db: Session) -> bool:
    return db.query(BootstrapSecret).filter(BootstrapSecret.username == BOOTSTRAP_USERNAME).count() > 0