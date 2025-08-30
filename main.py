from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from pydantic import BaseModel
from supabase import create_client
from passlib.context import CryptContext
from uuid import uuid4
from jose import jwt, JWTError
from dotenv import load_dotenv
from typing import Optional
import os

# ================================
# Load environment
# ================================
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ================================
# Security
# ================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = HTTPBearer()

def create_access_token(data: dict):
    return jwt.encode(data, JWT_SECRET, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ================================
# Schemas
# ================================
class User(BaseModel):
    email: str
    password: str
    username: str

class Profile(BaseModel):
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    privacy: Optional[str] = "public"

class Post(BaseModel):
    title: str
    content: str
    category: Optional[str] = None
    image_url: Optional[str] = None

class Comment(BaseModel):
    content: str

# ================================
# FastAPI app
# ================================
app = FastAPI()

# ================================
# Auth Endpoints
# ================================
@app.post("/register")
def register(user: User):
    hashed = pwd_context.hash(user.password)
    user_id = str(uuid4())
    data = supabase.table("users").insert({
        "id": user_id,
        "email": user.email,
        "password": hashed,
        "username": user.username
    }).execute()
    if getattr(data, "error", None):
        raise HTTPException(status_code=400, detail=data.error)
    return {"message": "User registered successfully", "id": user_id}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_data = supabase.table("users").select("*").eq("email", form_data.username).execute()
    if not user_data.data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = user_data.data[0]
    if not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"user_id": user["id"]})
    return {"access_token": token, "token_type": "bearer"}

# ================================
# Profile Endpoints
# ================================
@app.get("/profile")
def get_profile(user_id: str = Depends(verify_token)):
    response = supabase.table("users").select("id, email, username, bio, avatar_url, privacy").eq("id", user_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="User not found")
    return response.data[0]

@app.put("/profile")
def update_profile(profile: Profile, user_id: str = Depends(verify_token)):
    response = supabase.table("users").update(profile.dict(exclude_none=True)).eq("id", user_id).execute()
    return {"message": "Profile updated", "profile": response.data[0]}

# ================================
# Post Endpoints
# ================================
@app.post("/posts")
def create_post(post: Post, user_id: str = Depends(verify_token)):
    if len(post.content) > 280:
        raise HTTPException(status_code=400, detail="Post content exceeds 280 characters")
    res = supabase.table("posts").insert({
        "author_id": user_id,
        "title": post.title,
        "content": post.content,
        "category": post.category,
        "image_url": post.image_url
    }).execute()
    return {"message": "Post created", "post": res.data[0]}

@app.get("/posts")
def list_posts(user_id: str = Depends(verify_token)):
    res = supabase.table("posts").select("*").eq("author_id", user_id).execute()
    return res.data

# ================================
# Comment Endpoints
# ================================
@app.post("/posts/{post_id}/comments")
def add_comment(post_id: str, comment: Comment, user_id: str = Depends(verify_token)):
    res = supabase.table("comments").insert({
        "post_id": post_id,
        "author_id": user_id,
        "content": comment.content,
    }).execute()
    if getattr(res, "error", None):
        raise HTTPException(status_code=400, detail=res.error)
    return {"message": "Comment added", "comment": res.data[0]}

@app.get("/posts/{post_id}/comments")
def list_comments(post_id: str, user_id: str = Depends(verify_token)):
    res = supabase.table("comments").select("*").eq("post_id", post_id).order("created_at").execute()
    return res.data

@app.delete("/comments/{comment_id}")
def delete_comment(comment_id: str, user_id: str = Depends(verify_token)):
    res = supabase.table("comments").select("*").eq("id", comment_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Comment not found")
    comment = res.data[0]
    if comment["author_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not allowed to delete this comment")
    supabase.table("comments").delete().eq("id", comment_id).execute()
    return {"message": "Comment deleted"}

