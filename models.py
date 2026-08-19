from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(
        String,
        unique=True,
        index=True
    )

    hashed_password = Column(String)

    role = Column(
        String,
        default="user"
    )

    failed_attempts = Column(
        Integer,
        default=0
    )

    is_locked = Column(
        Boolean,
        default=False
    )

class Blacklist(Base):
    __tablename__ = "blacklist"

    token = Column(
        String,
        primary_key=True
    )

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    token = Column(
        String,
        primary_key=True
    )

    user_id = Column(Integer)

class ResetToken(Base):
    __tablename__ = "reset_tokens"

    token = Column(
        String,
        primary_key=True
    )

    user_id = Column(Integer)