from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, timezone
import uuid
import config

SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token() -> str:
    return str(uuid.uuid4())

def get_refresh_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)

def get_reset_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=config.RESET_TOKEN_EXPIRE_MINUTES)
