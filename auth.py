"""
synapse-auth/auth.py

JWT token logic.

Token payload:
  sub   — user ID
  email — user email
  plan  — basic | pro
  jti   — unique token ID (for revocation)
  iat   — issued at
  exp   — expiry

Design:
  - Tokens are valid for JWT_EXPIRY_DAYS (default 30)
  - Client should refresh when JWT_REFRESH_BEFORE_DAYS remain (default 7)
  - Tokens can be revoked immediately via the RevokedToken table
  - Client validates locally (checks signature + expiry) for offline use
  - Client hits /license/validate every 24h to check for revocation
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from models import RevokedToken

load_dotenv()

SECRET       = os.getenv("JWT_SECRET", "CHANGE_ME_BEFORE_PRODUCTION")
ALGORITHM    = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRY_DAYS  = int(os.getenv("JWT_EXPIRY_DAYS", "30"))
REFRESH_DAYS = int(os.getenv("JWT_REFRESH_BEFORE_DAYS", "7"))


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── Token creation ────────────────────────────────────────────────────────────

def create_license_token(user_id: str, email: str, plan: str) -> dict:
    """
    Create a signed JWT license token.
    Returns {"token": "...", "expires_at": "ISO string", "needs_refresh_after": "ISO string"}
    """
    now        = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(days=EXPIRY_DAYS)
    jti        = str(uuid.uuid4())

    payload = {
        "sub":   user_id,
        "email": email,
        "plan":  plan,
        "jti":   jti,
        "iat":   now,
        "exp":   expires_at,
    }

    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)

    # Client should refresh when this many days remain
    refresh_after = expires_at - timedelta(days=REFRESH_DAYS)

    return {
        "token":              token,
        "expires_at":         expires_at.isoformat(),
        "needs_refresh_after": refresh_after.isoformat(),
    }


# ── Token validation ──────────────────────────────────────────────────────────

class TokenError(Exception):
    """Raised when a token is invalid, expired, or revoked."""
    pass


def decode_token(token: str) -> dict:
    """
    Decode and verify a JWT. Returns the payload.
    Raises TokenError if invalid or expired.
    """
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise TokenError("Token has expired. Please refresh your license.")
    except jwt.InvalidTokenError as e:
        raise TokenError(f"Invalid token: {e}")


def validate_token(token: str, db: Session) -> dict:
    """
    Full validation: signature + expiry + revocation check.
    Call this on the server for every /license/validate request.
    Returns payload if valid, raises TokenError otherwise.
    """
    payload = decode_token(token)

    # Check revocation table
    jti     = payload.get("jti")
    revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if revoked:
        raise TokenError(f"Token has been revoked: {revoked.reason}")

    return payload


def revoke_token(jti: str, user_id: str, reason: str, db: Session):
    """Add a JTI to the revocation list."""
    entry = RevokedToken(jti=jti, user_id=user_id, reason=reason)
    db.add(entry)
    db.commit()


def should_refresh(token: str) -> bool:
    """
    Returns True if the token should be refreshed soon.
    Client calls this locally without hitting the server.
    """
    try:
        payload    = decode_token(token)
        exp        = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        refresh_at = exp - timedelta(days=REFRESH_DAYS)
        return datetime.now(tz=timezone.utc) >= refresh_at
    except TokenError:
        return True
