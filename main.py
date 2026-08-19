from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from bson import ObjectId
import uuid

from database import (
    users_collection,
    blacklist_collection,
    refresh_collection,
    reset_collection
)

from schemas import (
    UserCreate,
    UserLogin,
    RefreshRequest,
    ResetRequest
)

from auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    SECRET_KEY,
    ALGORITHM
)

app = FastAPI()

security = HTTPBearer()


# =========================
# CURRENT USER
# =========================

def get_current_user(
    token: HTTPAuthorizationCredentials = Depends(security)
):

    blacklisted = blacklist_collection.find_one(
        {
            "token": token.credentials
        }
    )

    if blacklisted:
        raise HTTPException(
            status_code=401,
            detail="Logged out token"
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
            status_code=401,
            detail="Invalid token"
        )


# =========================
# SIGNUP
# =========================

@app.post("/signup")
def signup(user: UserCreate):

    existing_user = users_collection.find_one(
        {
            "email": user.email
        }
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User already exists"
        )

    users_collection.insert_one(
        {
            "email": user.email,
            "hashed_password": hash_password(
                user.password
            ),
            "role": "user",
            "failed_attempts": 0,
            "is_locked": False
        }
    )

    return {
        "message": "User created"
    }


# =========================
# LOGIN
# =========================

@app.post("/login")
def login(user: UserLogin):

    db_user = users_collection.find_one(
        {
            "email": user.email
        }
    )

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if db_user["is_locked"]:
        raise HTTPException(
            status_code=403,
            detail="Account locked"
        )

    if not verify_password(
        user.password,
        db_user["hashed_password"]
    ):

        users_collection.update_one(
            {
                "email": user.email
            },
            {
                "$inc": {
                    "failed_attempts": 1
                }
            }
        )

        if db_user["failed_attempts"] + 1 >= 3:

            users_collection.update_one(
                {
                    "email": user.email
                },
                {
                    "$set": {
                        "is_locked": True
                    }
                }
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    users_collection.update_one(
        {
            "email": user.email
        },
        {
            "$set": {
                "failed_attempts": 0
            }
        }
    )

    access_token = create_access_token(
        {
            "id": str(db_user["_id"]),
            "role": db_user["role"]
        }
    )

    refresh_token = create_refresh_token()

    refresh_collection.insert_one(
        {
            "token": refresh_token,
            "user_id": str(db_user["_id"])
        }
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


# =========================
# REFRESH TOKEN
# =========================

@app.post("/refresh")
def refresh(
    data: RefreshRequest
):

    token = refresh_collection.find_one(
        {
            "token": data.refresh_token
        }
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    access_token = create_access_token(
        {
            "id": token["user_id"]
        }
    )

    return {
        "access_token": access_token
    }


# =========================
# LOGOUT
# =========================

@app.post("/logout")
def logout(
    token: HTTPAuthorizationCredentials = Depends(security)
):

    blacklist_collection.insert_one(
        {
            "token": token.credentials
        }
    )

    return {
        "message": "Logged out"
    }


# =========================
# PROFILE
# =========================

@app.get("/profile")
def profile(
    user=Depends(
        get_current_user
    )
):
    return user


# =========================
# ADMIN USERS
# =========================

@app.get("/admin/users")
def admin_users(
    user=Depends(
        get_current_user
    )
):

    if user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admins only"
        )

    users = list(
        users_collection.find(
            {},
            {
                "hashed_password": 0
            }
        )
    )

    for u in users:
        u["_id"] = str(u["_id"])

    return users


# =========================
# FORGOT PASSWORD
# =========================

@app.post("/forgot")
def forgot_password(
    email: str
):

    user = users_collection.find_one(
        {
            "email": email
        }
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    token = str(uuid.uuid4())

    reset_collection.insert_one(
        {
            "token": token,
            "user_id": str(user["_id"])
        }
    )

    return {
        "reset_token": token
    }


# =========================
# RESET PASSWORD
# =========================

@app.post("/reset")
def reset_password(
    data: ResetRequest
):

    reset = reset_collection.find_one(
        {
            "token": data.token
        }
    )

    if not reset:
        raise HTTPException(
            status_code=400,
            detail="Invalid token"
        )

    users_collection.update_one(
        {
            "_id": ObjectId(
                reset["user_id"]
            )
        },
        {
            "$set": {
                "hashed_password":
                hash_password(
                    data.new_password
                )
            }
        }
    )

    reset_collection.delete_one(
        {
            "token": data.token
        }
    )

    return {
        "message": "Password updated"
    }


# =========================
# ROOT
# =========================

@app.get("/")
def root():
    return {
        "message": "MongoDB Auth API Running"
    }