from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime
from app.models import VulnStatus, SeverityLevel
from typing import Optional

class UserRegister(BaseModel):
    """Schema for user registration."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    is_active: bool = True


class UserLogin(BaseModel):
    """Schema for login (form data)."""
    username: str
    password: str


class Token(BaseModel):
    """Response schema for JWT tokens."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # Expiration time in seconds


class UserResponse(BaseModel):
    """Public view of a user (never send password/hash)."""
    id: int
    username: str
    email: str
    is_active: bool