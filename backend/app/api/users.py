from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserResponse, UserUpdate, UserCreate
from app.auth import get_current_user, require_admin, hash_password

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.post("", response_model=UserResponse, status_code=201)
def create_user(
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


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user_data.full_name is not None:
        user.full_name = user_data.full_name
    if user_data.password:
        user.password_hash = hash_password(user_data.password)
    if user_data.role is not None and user_data.role != user.role:
        if user.id == current_user.id:
            raise HTTPException(status_code=400, detail="Нельзя изменить собственную роль")
        if user.role == "admin":
            admins = db.query(User).filter(User.role == "admin").count()
            if admins <= 1:
                raise HTTPException(status_code=400, detail="Нельзя удалить последнего администратора")
        user.role = user_data.role
    if user_data.is_active is not None:
        if user.id == current_user.id and not user_data.is_active:
            raise HTTPException(status_code=400, detail="Нельзя отключить собственную учётную запись")
        if user_data.is_active is False and user.role == "admin":
            admins = db.query(User).filter(User.role == "admin", User.is_active == True).count()
            if admins <= 1:
                raise HTTPException(status_code=400, detail="Нельзя отключить последнего администратора")
        user.is_active = user_data.is_active
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить самого себя")
    if user.role == "admin":
        admins = db.query(User).filter(User.role == "admin").count()
        if admins <= 1:
            raise HTTPException(status_code=400, detail="Нельзя удалить последнего администратора")
    db.delete(user)
    db.commit()
