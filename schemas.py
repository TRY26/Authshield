from pydantic import BaseModel, Field
import re

# Resilient Email type fallback
try:
    from pydantic import EmailStr
    # Test if email-validator is functional
    class _EmailProbe(BaseModel):
        email: EmailStr
except Exception:
    # Regex fallback if email-validator package is not installed
    try:
        from pydantic import StringConstraints
        from typing import Annotated
        EmailStr = Annotated[str, StringConstraints(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    except ImportError:
        EmailStr = str

def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_]", password):
        raise ValueError("Password must contain at least one special character.")
    return password

# Check for Pydantic v2 vs v1
try:
    from pydantic import field_validator
    USE_V2 = True
except ImportError:
    from pydantic import validator
    USE_V2 = False

if USE_V2:
    class UserCreate(BaseModel):
        email: EmailStr
        password: str = Field(min_length=8, max_length=50)

        @field_validator("password")
        @classmethod
        def check_password(cls, v):
            return validate_password_strength(v)

    class ResetRequest(BaseModel):
        token: str
        new_password: str = Field(min_length=8, max_length=50)

        @field_validator("new_password")
        @classmethod
        def check_password(cls, v):
            return validate_password_strength(v)
else:
    class UserCreate(BaseModel):
        email: EmailStr
        password: str = Field(min_length=8, max_length=50)

        @validator("password")
        def check_password(cls, v):
            return validate_password_strength(v)

    class ResetRequest(BaseModel):
        token: str
        new_password: str = Field(min_length=8, max_length=50)

        @validator("new_password")
        def check_password(cls, v):
            return validate_password_strength(v)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ForgotRequest(BaseModel):
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
