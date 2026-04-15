from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from jose import JWTError
import structlog

from app.database import get_db
from app.models import User, Vulnerability, Scan
from app.auth import get_password_hash

logger = structlog.get_logger()


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify JWT token and return active user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token)
        if payload is None:
            logger.warning("invalid_token_attempt")
            raise credentials_exception
            
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
            
        # Eager load: Eagerly load the relationship to avoid N+1 queries
        result = await db.execute(select(User).options(selectinload(User)).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if user is None:
            raise credentials_exception
            
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user"
            )
            
        return user
        
    except JWTError:
        logger.warning("token_validation_failed", error=str(e))
        raise credentials_exception


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Additional check to ensure user is active (RBAC)."""
    if not current_user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")
    return current_user