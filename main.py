from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from jose import jwt, JWTError
from bson import ObjectId
from datetime import datetime, timezone
from collections import defaultdict
import threading
import time
import os
import uuid
import logging

logger = logging.getLogger("authshield")

# Rate limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
    HAS_SLOWAPI = True
except ImportError:
    HAS_SLOWAPI = False
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

# In-memory sliding window rate limiter (Defensive guarantee)
class SlidingWindowLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def check(self, ip: str, limit: int = 5, window_seconds: int = 60) -> bool:
        now = time.time()
        with self.lock:
            self.requests[ip] = [t for t in self.requests[ip] if now - t < window_seconds]
            if len(self.requests[ip]) >= limit:
                return False  # Exceeded limit
            self.requests[ip].append(now)
            return True  # Allowed

login_limiter = SlidingWindowLimiter()
signup_limiter = SlidingWindowLimiter()
forgot_limiter = SlidingWindowLimiter()

import config
import database
from schemas import (
    UserCreate,
    UserLogin,
    RefreshRequest,
    ResetRequest,
    ForgotRequest,
    TokenResponse
)
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    get_refresh_token_expiry,
    get_reset_token_expiry,
    SECRET_KEY,
    ALGORITHM
)

app = FastAPI(
    title="AuthShield API",
    description="Enterprise-grade CIAM authentication service with Refresh Token Rotation (RTR), Rate Limiting, and Automated Reuse Detection.",
    version="2.0.0"
)

# Global Exception Handler for transparent error debugging
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "error_type": type(exc).__name__}
    )

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiter setup
if HAS_SLOWAPI:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

security = HTTPBearer()

def require_db():
    if database.users_collection is None:
        database.get_database()


def parse_datetime(dt_val):
    if dt_val is None:
        return None
    if isinstance(dt_val, str):
        try:
            return datetime.fromisoformat(dt_val)
        except Exception:
            return None
    return dt_val


# =========================
# HELPER: CURRENT USER
# =========================

def get_current_user(token: HTTPAuthorizationCredentials = Depends(security)):
    require_db()
    blacklisted = database.blacklist_collection.find_one({"token": token.credentials})
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been terminated (token blacklisted)."
        )

    try:
        payload = jwt.decode(
            token.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token."
        )


# =========================
# HEALTH CHECK
# =========================

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "AuthShield CIAM API",
        "version": "2.0.0",
        "database": database.engine_mode,
        "rate_limiting_active": True
    }


# =========================
# SIGNUP
# =========================

@app.post("/signup", tags=["Authentication"])
@limiter.limit("10/minute")
def signup(request: Request, user: UserCreate):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not signup_limiter.check(client_ip, limit=10, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: Maximum 10 signup requests per minute."
        )

    require_db()
    existing_user = database.users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    new_user = {
        "email": user.email,
        "hashed_password": hash_password(user.password),
        "role": "user",
        "failed_attempts": 0,
        "is_locked": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    result = database.users_collection.insert_one(new_user)
    return {
        "message": "User registered successfully.",
        "user_id": str(result.inserted_id)
    }


# =========================
# LOGIN (WITH DEFENSIVE LOCKOUT & REFRESH TOKENS)
# =========================

@app.post("/login", response_model=TokenResponse, tags=["Authentication"])
@limiter.limit("5/minute")
def login(request: Request, user: UserLogin):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not login_limiter.check(client_ip, limit=5, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: Maximum 5 login requests per minute. Brute force defense active."
        )

    require_db()
    db_user = database.users_collection.find_one({"email": user.email})
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found."
        )

    if db_user.get("is_locked", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account locked due to consecutive failed login attempts. Please reset your password."
        )

    if not verify_password(user.password, db_user["hashed_password"]):
        failed_attempts = db_user.get("failed_attempts", 0) + 1
        is_locked = failed_attempts >= 3

        database.users_collection.update_one(
            {"email": user.email},
            {"$set": {"failed_attempts": failed_attempts, "is_locked": is_locked}}
        )

        if is_locked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been locked after 3 failed attempts."
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid credentials. {3 - failed_attempts} attempts remaining before lockout."
        )

    # Reset failed attempts on successful login
    database.users_collection.update_one(
        {"email": user.email},
        {"$set": {"failed_attempts": 0}}
    )

    user_id = str(db_user.get("_id"))

    access_token = create_access_token({
        "id": user_id,
        "email": db_user["email"],
        "role": db_user.get("role", "user")
    })

    refresh_token = create_refresh_token()
    database.refresh_collection.insert_one({
        "token": refresh_token,
        "user_id": user_id,
        "expires_at": get_refresh_token_expiry().isoformat(),
        "revoked": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# =========================
# REFRESH TOKEN ROTATION (RTR) WITH REUSE DETECTION
# =========================

@app.post("/refresh", response_model=TokenResponse, tags=["Authentication"])
@limiter.limit("20/minute")
def refresh(request: Request, data: RefreshRequest):
    require_db()
    token_doc = database.refresh_collection.find_one({"token": data.refresh_token})

    # AUTOMATIC REUSE DETECTION (RFC 6749 Token Theft Mitigation)
    if token_doc and token_doc.get("revoked", False):
        database.refresh_collection.update_many(
            {"user_id": token_doc["user_id"]},
            {"$set": {"revoked": True, "compromised_at": datetime.now(timezone.utc).isoformat()}}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security Alert: Revoked refresh token reuse detected. All sessions terminated for security."
        )

    if not token_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token."
        )

    # Check expiration
    expires_at = parse_datetime(token_doc.get("expires_at"))
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired. Please log in again."
            )

    # Rotate token: Invalidate current refresh token
    database.refresh_collection.update_one(
        {"token": data.refresh_token},
        {"$set": {"revoked": True, "rotated_at": datetime.now(timezone.utc).isoformat()}}
    )

    # Retrieve user to retain role and claims
    target_id = token_doc["user_id"]
    user = database.users_collection.find_one({"_id": target_id})
    if not user:
        try:
            user = database.users_collection.find_one({"_id": ObjectId(target_id)})
        except Exception:
            pass

    if not user or user.get("is_locked", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is locked or deactivated."
        )

    new_access_token = create_access_token({
        "id": str(user.get("_id", target_id)),
        "email": user["email"],
        "role": user.get("role", "user")
    })

    new_refresh_token = create_refresh_token()
    database.refresh_collection.insert_one({
        "token": new_refresh_token,
        "user_id": target_id,
        "expires_at": get_refresh_token_expiry().isoformat(),
        "revoked": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }


# =========================
# LOGOUT (SESSION REVOCATION)
# =========================

@app.post("/logout", tags=["Authentication"])
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    refresh_token: str = None
):
    require_db()
    database.blacklist_collection.insert_one({
        "token": credentials.credentials,
        "blacklisted_at": datetime.now(timezone.utc).isoformat()
    })

    if refresh_token:
        database.refresh_collection.update_one(
            {"token": refresh_token},
            {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc).isoformat()}}
        )

    return {"message": "Session terminated and token blacklisted successfully."}


# =========================
# USER PROFILE (PROTECTED)
# =========================

@app.get("/profile", tags=["User"])
def profile(user=Depends(get_current_user)):
    return {
        "authenticated": True,
        "user_id": user.get("id"),
        "email": user.get("email"),
        "role": user.get("role")
    }


# =========================
# ADMIN ROUTE (RBAC GUARD)
# =========================

@app.get("/admin/users", tags=["Admin"])
def admin_users(user=Depends(get_current_user)):
    require_db()
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Requires administrator privileges."
        )

    users = list(database.users_collection.find({}, {"hashed_password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])

    return users


@app.post("/admin/unlock/{user_id}", tags=["Admin"])
def admin_unlock(user_id: str, user=Depends(get_current_user)):
    require_db()
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Requires administrator privileges."
        )

    result = database.users_collection.update_one(
        {"_id": user_id},
        {"$set": {"is_locked": False, "failed_attempts": 0}}
    )
    if result.matched_count == 0:
        try:
            result = database.users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"is_locked": False, "failed_attempts": 0}}
            )
        except Exception:
            pass

    return {"message": f"User {user_id} unlocked successfully."}


# =========================
# PASSWORD RECOVERY (TIME-BOUND)
# =========================

@app.post("/forgot", tags=["Password Recovery"])
@limiter.limit("3/minute")
def forgot_password(request: Request, data: ForgotRequest):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not forgot_limiter.check(client_ip, limit=3, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: Maximum 3 password reset requests per minute."
        )

    require_db()
    user = database.users_collection.find_one({"email": data.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account registered with this email address."
        )

    user_id = str(user.get("_id"))
    reset_token = str(uuid.uuid4())
    expires_at = get_reset_token_expiry().isoformat()

    # Invalidate previous tokens for this user
    database.reset_collection.delete_many({"user_id": user_id})

    database.reset_collection.insert_one({
        "token": reset_token,
        "user_id": user_id,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    return {
        "message": "Password reset token generated (valid for 15 minutes).",
        "reset_token": reset_token,
        "expires_in_minutes": config.RESET_TOKEN_EXPIRE_MINUTES
    }


@app.post("/reset", tags=["Password Recovery"])
@limiter.limit("5/minute")
def reset_password(request: Request, data: ResetRequest):
    require_db()
    reset_doc = database.reset_collection.find_one({"token": data.token})
    if not reset_doc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already-used reset token."
        )

    expires_at = parse_datetime(reset_doc.get("expires_at"))
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            database.reset_collection.delete_one({"token": data.token})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired. Please request a new one."
            )

    user_id = reset_doc["user_id"]
    update_res = database.users_collection.update_one(
        {"_id": user_id},
        {
            "$set": {
                "hashed_password": hash_password(data.new_password),
                "is_locked": False,
                "failed_attempts": 0
            }
        }
    )
    if update_res.matched_count == 0:
        try:
            database.users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "hashed_password": hash_password(data.new_password),
                        "is_locked": False,
                        "failed_attempts": 0
                    }
                }
            )
        except Exception:
            pass

    # Single-use: Consume reset token immediately
    database.reset_collection.delete_one({"token": data.token})

    return {"message": "Password updated successfully. Account is active."}


# =========================
# INTERACTIVE DEMO UI (SERVED AT /)
# =========================

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_FILE = os.path.join(STATIC_DIR, "index.html")

@app.get("/", include_in_schema=False)
def serve_home():
    if os.path.exists(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    return {
        "message": "AuthShield CIAM API v2.0 Running. Visit /docs for OpenAPI specifications."
    }

@app.get("/demo", include_in_schema=False)
def serve_demo():
    if os.path.exists(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    return {"message": "Demo UI not found. Check static/index.html"}
