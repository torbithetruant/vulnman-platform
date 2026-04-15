from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
import structlog

from app.database import get_db
from app.models import User
from app.schemas import UserRegister, Token
from app.auth import verify_password, get_password_hash
from app.config import settings

from jose import jwt

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = structlog.get_logger()

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db) # FIXED: AsyncSession, not AuthSession
):
    logger.info("registration_attempt", username=user_data.username)
    
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already registered")
    
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password), # Hash on creation
        is_active=True # FIXED: Added missing comma
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    return {"id": user.id, "username": user.username, "message": "User created successfully"}

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    logger.info("login_attempt", username=form_data.username)
    
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()
    
    # FIXED: Use verify_password, not get_password_hash. Fixed typo in form_data.
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning("login_failed_invalid", username=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    
    # FIXED: Use datetime.now(timezone.utc) instead of deprecated utcnow
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    to_encode = {
        "sub": user.username,
        "user_id": user.id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + access_token_expires
    }
    
    access_token = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    
    return {"access_token": access_token, "token_type": "bearer", "expires_in": settings.access_token_expire_minutes * 60}