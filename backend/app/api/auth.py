import logging
import secrets
import string
import time
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db, engine
from app.models import User, BootstrapSecret, LoginAttempt
from app.schemas import UserCreate, UserResponse, Token
from app.auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_admin,
)
from app.config import BOOTSTRAP_USERNAME, BOOTSTRAP_FULL_NAME, MAX_PASSWORD_LENGTH

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300

_PASSWORD_ALPHABET = "".join(
    ch for ch in (string.ascii_letters + string.digits) if ch not in "0O1lI"
)


def _init_login_attempts():
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip VARCHAR(45) NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    attempts INTEGER DEFAULT 1,
                    first_attempt_at DATETIME NOT NULL
                )
            """))
            conn.commit()
    except Exception:
        pass


_init_login_attempts()


def _check_login_throttle(ip: str, username: str):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=_LOGIN_WINDOW_SECONDS)
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM login_attempts WHERE first_attempt_at < :cutoff"), {"cutoff": cutoff})
        row = conn.execute(
            text("SELECT id, attempts, first_attempt_at FROM login_attempts WHERE ip = :ip AND username = :username"),
            {"ip": ip, "username": username},
        ).fetchone()
        if row:
            attempt_id, attempts, first_at = row
            if attempts >= _LOGIN_MAX_ATTEMPTS:
                raise HTTPException(status_code=429, detail="Слишком много попыток входа. Попробуйте позже.")
            conn.execute(
                text("UPDATE login_attempts SET attempts = attempts + 1 WHERE id = :id"),
                {"id": attempt_id},
            )
        else:
            conn.execute(
                text("INSERT INTO login_attempts (ip, username, attempts, first_attempt_at) VALUES (:ip, :username, 1, :now)"),
                {"ip": ip, "username": username, "now": now},
            )
        conn.commit()


def _login_success(ip: str, username: str):
    with engine.connect() as conn:
        conn.execute(
            text("DELETE FROM login_attempts WHERE ip = :ip AND username = :username"),
            {"ip": ip, "username": username},
        )
        conn.commit()


def _generate_password() -> str:
    group = lambda: "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(4))
    return "-".join(group() for _ in range(3))


def ensure_bootstrap(db: Session) -> str | None:
    """Create admin user with random one-time password if no users exist.

    Returns the plaintext password (to be logged once), or None if already set up.
    The password is stored as a bcrypt hash in bootstrap_secrets.
    """
    if db.query(User).count() > 0:
        return None

    db.query(BootstrapSecret).delete()
    password = _generate_password()
    password_hash = hash_password(password)

    user = User(
        username=BOOTSTRAP_USERNAME,
        password_hash=hash_password(password),
        role="admin",
        full_name=BOOTSTRAP_FULL_NAME,
    )
    db.add(user)
    db.add(BootstrapSecret(username=user.username, secret=password_hash))
    db.commit()
    return password


def _bootstrap_exists(db: Session) -> bool:
    return (
        db.query(BootstrapSecret)
        .filter(BootstrapSecret.used == False)
        .first()
        is not None
    )


def _consume_bootstrap_secrets(db: Session, username: str):
    rows = db.query(BootstrapSecret).filter(BootstrapSecret.username == username).all()
    if rows:
        for row in rows:
            db.delete(row)
        db.commit()


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    user_count = db.query(User).count()
    needs_setup = user_count == 0 or _bootstrap_exists(db)
    return {
        "needs_setup": needs_setup,
        "user_count": user_count,
    }


@router.post("/login", response_model=Token)
def login(form_data: dict, request: Request, db: Session = Depends(get_db)):
    username = (form_data.get("username") or "").strip()
    password = form_data.get("password") or ""

    if len(username) > 100 or len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail="Неверные учётные данные")

    ip = request.client.host if request.client else "unknown"
    _check_login_throttle(ip, username)

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        logger.warning("Login failed: user=%s ip=%s reason=invalid_password", username, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
        )
    if not user.is_active:
        logger.warning("Login failed: user=%s ip=%s reason=account_disabled", username, ip)
        raise HTTPException(status_code=403, detail="Учётная запись отключена")

    logger.info("Login success: user=%s ip=%s", username, ip)
    _login_success(ip, username)
    _consume_bootstrap_secrets(db, user.username)
    token = create_access_token(data={"sub": user.username, "role": user.role})
    return Token(access_token=token, role=user.role, username=user.username)


@router.post("/register", response_model=UserResponse, status_code=201)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        full_name=user_data.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user
