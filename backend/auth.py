import os
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import bcrypt
import pyotp
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret")
JWT_ALGO = "HS256"
TOKEN_EXPIRE_MIN = 60 * 8  # 8 ghante

# --- Password (bcrypt directly, passlib nahi) ---
def hash_password(plain: str) -> str:
    # bcrypt 72 byte limit -- truncate safely
    pw = plain.encode("utf-8")[:72]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    pw = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(pw, hashed.encode("utf-8"))

# --- JWT token ---
def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload.get("sub")
    except JWTError:
        return None

# --- TOTP (MFA) ---
def verify_totp(secret: str, code: str) -> bool:
    if not secret:
        return True
    return pyotp.TOTP(secret).verify(code, valid_window=1)
