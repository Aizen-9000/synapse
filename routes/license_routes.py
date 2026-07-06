"""
synapse-auth/routes/license_routes.py

GET  /license/validate  → check if a token is still valid (called by client every 24h)
POST /license/refresh   → issue a fresh token (called by client when near expiry)
POST /license/revoke    → admin: revoke a token immediately
"""

from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import User, License
from auth import (
    validate_token, create_license_token,
    decode_token, revoke_token, TokenError,
)

router = APIRouter(prefix="/license", tags=["license"])


def _extract_token(authorization: str = Header(...)) -> str:
    """Parse Bearer token from Authorization header."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header must be 'Bearer <token>'")
    return authorization[len("Bearer "):]


# ── Schemas ───────────────────────────────────────────────────────────────────

class RevokeRequest(BaseModel):
    token: str
    reason: str = "manual revocation"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/validate")
def validate(authorization: str = Header(...), db: Session = Depends(get_db)):
    """
    Full token validation: signature + expiry + revocation check.
    Client calls this every 24 hours.
    Returns {"valid": true/false, "reason": "...", "plan": "...", "expires_at": "..."}
    """
    token = _extract_token(authorization)

    try:
        payload = validate_token(token, db)
    except TokenError as e:
        return {"valid": False, "reason": str(e)}

    # Also check that the license is still active in our DB
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.license or not user.license.is_valid:
        status = user.license.status if user and user.license else "unknown"
        return {"valid": False, "reason": f"License is {status}"}

    return {
        "valid":      True,
        "plan":       payload.get("plan", "basic"),
        "email":      payload.get("email"),
        "expires_at": payload.get("exp"),
    }


@router.post("/refresh")
def refresh(authorization: str = Header(...), db: Session = Depends(get_db)):
    """
    Issue a new token in exchange for a still-valid one.
    Client calls this when the token is near expiry (JWT_REFRESH_BEFORE_DAYS remaining).
    Old token is revoked, new one issued.
    """
    token = _extract_token(authorization)

    try:
        payload = validate_token(token, db)
    except TokenError as e:
        raise HTTPException(status_code=401, detail=str(e))

    user_id = payload["sub"]
    user    = db.query(User).filter(User.id == user_id).first()

    if not user or not user.license or not user.license.is_valid:
        raise HTTPException(status_code=402, detail="License is not active. Please renew your subscription.")

    # Revoke old token
    revoke_token(payload["jti"], user_id, "refreshed", db)

    # Issue new token
    new_token = create_license_token(user_id, user.email, user.license.plan)

    return {
        "token":               new_token["token"],
        "expires_at":          new_token["expires_at"],
        "needs_refresh_after": new_token["needs_refresh_after"],
        "plan":                user.license.plan,
    }


@router.post("/revoke")
def revoke(req: RevokeRequest, db: Session = Depends(get_db)):
    """
    Admin endpoint: immediately revoke a token by JTI.
    Call this when a user cancels or payment fails.
    """
    try:
        payload = decode_token(req.token)
    except TokenError as e:
        raise HTTPException(status_code=400, detail=str(e))

    revoke_token(payload["jti"], payload["sub"], req.reason, db)
    return {"revoked": True, "jti": payload["jti"], "reason": req.reason}
