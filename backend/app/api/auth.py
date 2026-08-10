import secrets
import string
import time
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, BootstrapSecret
from app.schemas import UserCreate, UserResponse, Token
from app.auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_admin,
)
from app.config import BOOTSTRAP_USERNAME, BOOTSTRAP_FULL_NAME

router = APIRouter(prefix="/api/auth", tags=["auth"])

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300
_login_attempts: dict[str, tuple[int, float]] = {}

_PASSWORD_ALPHABET = "".join(
    ch for ch in (string.ascii_letters + string.digits) if ch not in "0O1lI"
)


def _check_login_throttle(key: str):
    now = time.monotonic()
    entry = _login_attempts.get(key)
    if not entry:
        _login_attempts[key] = (1, now)
        return
    count, first = entry
    if now - first > _LOGIN_WINDOW_SECONDS:
        _login_attempts[key] = (1, now)
        return
    if count >= _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Слишком много попыток входа. Попробуйте позже.")
    _login_attempts[key] = (count + 1, first)


def _login_success(key: str):
    _login_attempts.pop(key, None)


def _generate_password() -> str:
    group = lambda: "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(4))
    return "-".join(group() for _ in range(3))


def _bootstrap_exists(db: Session) -> bool:
    return (
        db.query(BootstrapSecret)
        .filter(BootstrapSecret.used == False)
        .first()
        is not None
    )


def ensure_bootstrap(db: Session):
    """Создаёт админа со случайным паролем, если пользователей нет.

    Одноразовый пароль хранится в БД (BootstrapSecret) и удаляется после
    первого успешного входа, поэтому не существует файла, который можно
    подменить или выкрасть.
    """
    if db.query(User).count() > 0:
        return
    db.query(BootstrapSecret).delete()
    password = _generate_password()
    user = User(
        username=BOOTSTRAP_USERNAME,
        password_hash=hash_password(password),
        role="admin",
        full_name=BOOTSTRAP_FULL_NAME,
    )
    db.add(user)
    db.add(BootstrapSecret(username=user.username, secret=password))
    db.commit()


def _get_unused_secret(db: Session) -> BootstrapSecret | None:
    return (
        db.query(BootstrapSecret)
        .filter(BootstrapSecret.used == False)
        .first()
    )


def _consume_bootstrap_secrets(db: Session, username: str):
    rows = db.query(BootstrapSecret).filter(BootstrapSecret.username == username).all()
    if rows:
        for row in rows:
            db.delete(row)
        db.commit()


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    ensure_bootstrap(db)
    user_count = db.query(User).count()
    needs_setup = _bootstrap_exists(db)
    return {
        "needs_setup": needs_setup,
        "user_count": user_count,
        "bootstrap_username": BOOTSTRAP_USERNAME if needs_setup else None,
    }


@router.get("/bootstrap")
def get_bootstrap(db: Session = Depends(get_db)):
    ensure_bootstrap(db)
    row = _get_unused_secret(db)
    if not row:
        raise HTTPException(
            status_code=404,
            detail="Временный пароль уже использован",
        )
    return {"username": row.username, "password": row.secret}


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


@router.post("/login", response_model=Token)
def login(form_data: dict, request: Request, db: Session = Depends(get_db)):
    username = (form_data.get("username") or "").strip()
    password = form_data.get("password") or ""
    ip = request.client.host if request.client else "unknown"
    key = f"{ip}:{username}"
    _check_login_throttle(key)
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Учётная запись отключена")
    _login_success(key)
    _consume_bootstrap_secrets(db, user.username)
    token = create_access_token(data={"sub": user.username, "role": user.role})
    return Token(access_token=token, role=user.role, username=user.username)


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user
