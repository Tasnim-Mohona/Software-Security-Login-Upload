from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime
import re

class UserCreate(BaseModel):
    first_name: str = Field(..., max_length=100)
    middle_name: Optional[str] = Field(None, max_length=100)
    last_name: str = Field(..., max_length=100)
    email: EmailStr = Field(..., max_length=255, description="Truncate buffer boundary protecting from memory exhaustion")
    password: str = Field(..., min_length=12, max_length=128, description="Must be at least 12 characters and contain uppercase, lowercase, number, and special character.") # Strong password enforcement
    role: Optional[str] = "user"

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Must contain at least one number")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Must contain at least one special character")
        return v

class UserChangePassword(BaseModel):
    old_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128, description="Must be at least 12 characters and contain uppercase, lowercase, number, and special character.")

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Must contain at least one number")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Must contain at least one special character")
        return v

class UserResponse(BaseModel):
    id: int
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
