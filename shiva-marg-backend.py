#!/usr/bin/env python3
"""
ShivaMarg Backend — Single-file FastAPI server
Auth (register/login/JWT) + Comments (CRUD) with MongoDB
Install: pip install fastapi uvicorn pymongo python-jose[cryptography] passlib[bcrypt] python-multipart
Run: uvicorn shivamarg_backend:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from pymongo import MongoClient, DESCENDING
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import os
import re

# ─────────────────────────────────────────────
#  CONFIG  (change these via env vars in prod)
# ─────────────────────────────────────────────
MONGO_URI        = os.getenv("MONGO_URI",  "mongodb://localhost:27017")
DB_NAME          = os.getenv("DB_NAME",    "shivamarg")
SECRET_KEY       = os.getenv("SECRET_KEY", "shiva-om-namah-supersecret-change-in-prod-2024")
ALGORITHM        = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7   # 7 days

ALLOWED_ORIGINS  = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ─────────────────────────────────────────────
#  APP + CORS
# ─────────────────────────────────────────────
app = FastAPI(title="ShivaMarg API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  DB
# ─────────────────────────────────────────────
client = MongoClient(MONGO_URI)
db     = client[DB_NAME]
users_col    = db["users"]
comments_col = db["comments"]

# Indexes
users_col.create_index("email",    unique=True)
users_col.create_index("username", unique=True)
comments_col.create_index([("page_id", 1), ("created_at", DESCENDING)])
comments_col.create_index("user_id")

# ─────────────────────────────────────────────
#  PASSWORD + JWT
# ─────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer(auto_error=False)

def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds:
        return None
    payload = decode_token(creds.credentials)
    user = users_col.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    user = get_current_user(creds)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def serialize_user(u: dict) -> dict:
    return {
        "id":         str(u["_id"]),
        "username":   u["username"],
        "email":      u["email"],
        "avatar":     u.get("avatar", u["username"][0].upper()),
        "created_at": u["created_at"].isoformat(),
    }

def serialize_comment(c: dict, current_user_id: Optional[str] = None) -> dict:
    likes      = c.get("likes", [])
    liked_by_me = (current_user_id in likes) if current_user_id else False
    return {
        "id":          str(c["_id"]),
        "page_id":     c["page_id"],
        "user_id":     c["user_id"],
        "username":    c["username"],
        "avatar":      c.get("avatar", c["username"][0].upper()),
        "text":        c["text"],
        "likes":       len(likes),
        "liked_by_me": liked_by_me,
        "created_at":  c["created_at"].isoformat(),
        "updated_at":  c.get("updated_at", c["created_at"]).isoformat(),
    }

# ─────────────────────────────────────────────
#  SCHEMAS
# ─────────────────────────────────────────────
class RegisterInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: str
    password: str = Field(..., min_length=6)
    display_name: Optional[str] = None

class LoginInput(BaseModel):
    email: str
    password: str

class CommentInput(BaseModel):
    page_id: str = Field(..., description="Unique page identifier e.g. 'shiv-aarti'")
    text: str    = Field(..., min_length=1, max_length=1000)

class CommentUpdate(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000)

# ─────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────
@app.post("/api/auth/register", status_code=201)
def register(body: RegisterInput):
    # Validate username
    if not re.match(r"^[a-zA-Z0-9_]+$", body.username):
        raise HTTPException(400, "Username can only contain letters, numbers, underscores")

    # Check duplicates
    if users_col.find_one({"email": body.email.lower()}):
        raise HTTPException(400, "Email already registered")
    if users_col.find_one({"username": body.username}):
        raise HTTPException(400, "Username already taken")

    doc = {
        "username":     body.username,
        "display_name": body.display_name or body.username,
        "email":        body.email.lower(),
        "password":     hash_password(body.password),
        "avatar":       body.username[0].upper(),
        "created_at":   datetime.utcnow(),
    }
    result = users_col.insert_one(doc)
    doc["_id"] = result.inserted_id

    token = create_token({"sub": str(result.inserted_id)})
    return {"token": token, "user": serialize_user(doc)}


@app.post("/api/auth/login")
def login(body: LoginInput):
    user = users_col.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(401, "Invalid email or password")

    token = create_token({"sub": str(user["_id"])})
    return {"token": token, "user": serialize_user(user)}


@app.get("/api/auth/me")
def me(current_user=Depends(require_user)):
    return serialize_user(current_user)


# ─────────────────────────────────────────────
#  COMMENT ROUTES
# ─────────────────────────────────────────────
@app.get("/api/comments/{page_id}")
def get_comments(
    page_id: str,
    skip: int = 0,
    limit: int = 20,
    creds: HTTPAuthorizationCredentials = Depends(bearer),
):
    current_user = get_current_user(creds)
    uid = str(current_user["_id"]) if current_user else None

    cursor = (
        comments_col
        .find({"page_id": page_id})
        .sort("created_at", DESCENDING)
        .skip(skip)
        .limit(limit)
    )
    total = comments_col.count_documents({"page_id": page_id})
    items = [serialize_comment(c, uid) for c in cursor]
    return {"total": total, "comments": items}


@app.post("/api/comments", status_code=201)
def post_comment(body: CommentInput, current_user=Depends(require_user)):
    doc = {
        "page_id":    body.page_id,
        "user_id":    str(current_user["_id"]),
        "username":   current_user["username"],
        "avatar":     current_user.get("avatar", current_user["username"][0].upper()),
        "text":       body.text.strip(),
        "likes":      [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = comments_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize_comment(doc, str(current_user["_id"]))


@app.put("/api/comments/{comment_id}")
def update_comment(
    comment_id: str,
    body: CommentUpdate,
    current_user=Depends(require_user),
):
    try:
        oid = ObjectId(comment_id)
    except Exception:
        raise HTTPException(400, "Invalid comment id")

    comment = comments_col.find_one({"_id": oid})
    if not comment:
        raise HTTPException(404, "Comment not found")
    if comment["user_id"] != str(current_user["_id"]):
        raise HTTPException(403, "Cannot edit another user's comment")

    comments_col.update_one(
        {"_id": oid},
        {"$set": {"text": body.text.strip(), "updated_at": datetime.utcnow()}}
    )
    updated = comments_col.find_one({"_id": oid})
    return serialize_comment(updated, str(current_user["_id"]))


@app.delete("/api/comments/{comment_id}", status_code=204)
def delete_comment(comment_id: str, current_user=Depends(require_user)):
    try:
        oid = ObjectId(comment_id)
    except Exception:
        raise HTTPException(400, "Invalid comment id")

    comment = comments_col.find_one({"_id": oid})
    if not comment:
        raise HTTPException(404, "Comment not found")
    if comment["user_id"] != str(current_user["_id"]):
        raise HTTPException(403, "Cannot delete another user's comment")

    comments_col.delete_one({"_id": oid})
    return None


@app.post("/api/comments/{comment_id}/like")
def toggle_like(comment_id: str, current_user=Depends(require_user)):
    try:
        oid = ObjectId(comment_id)
    except Exception:
        raise HTTPException(400, "Invalid comment id")

    comment = comments_col.find_one({"_id": oid})
    if not comment:
        raise HTTPException(404, "Comment not found")

    uid  = str(current_user["_id"])
    likes = comment.get("likes", [])

    if uid in likes:
        comments_col.update_one({"_id": oid}, {"$pull": {"likes": uid}})
        liked = False
    else:
        comments_col.update_one({"_id": oid}, {"$push": {"likes": uid}})
        liked = True

    updated = comments_col.find_one({"_id": oid})
    return serialize_comment(updated, uid)


# ─────────────────────────────────────────────
#  HEALTH
# ─────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "db": DB_NAME}


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("shivamarg_backend:app", host="0.0.0.0", port=8000, reload=True)
