from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import uuid

SECRET_KEY = "super_secret_key"

ALGORITHM = "HS256"

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(
    password,
    hashed_password
):
    return pwd_context.verify(
        password,
        hashed_password
    )

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=15
    )

    to_encode.update(
        {"exp": expire}
    )

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

def create_refresh_token():
    return str(uuid.uuid4())