"""
synapse-auth/routes/auth_routes.py

POST /auth/signup              → create account
POST /auth/login               → get JWT
POST /auth/create-subscription → create Razorpay subscription (after signup)
"""

import os
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from database import get_db
from models import User, License
from auth import hash_password, verify_password, create_license_token
from razorpay_handler import create_subscription

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    email: str
    password: str
    name: str = ""
    plan: str = "basic"     # basic | pro


class LoginRequest(BaseModel):
    email: str
    password: str


class SubscriptionRequest(BaseModel):
    email: str
    plan: str = "basic"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/signup")
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    """Create a new user account. Does not activate license yet — payment required."""
    # Check duplicate
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    # Validate plan
    if req.plan not in ("basic", "pro"):
        raise HTTPException(status_code=400, detail="Plan must be 'basic' or 'pro'.")

    # Create user
    user = User(
        email=req.email,
        password_hash=hash_password(req.password),
        name=req.name or req.email.split("@")[0],
    )
    db.add(user)
    db.flush()  # get user.id before committing

    # Create pending license
    license_ = License(user_id=user.id, plan=req.plan, status="pending")
    db.add(license_)
    db.commit()
    db.refresh(user)

    return {
        "user_id": user.id,
        "email":   user.email,
        "message": "Account created. Complete payment to activate your license.",
    }


@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate and return a JWT license token.
    Only works if the user has an active license.
    """
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is suspended.")

    license_ = user.license
    if not license_:
        raise HTTPException(status_code=402, detail="No license found. Please complete payment.")

    if not license_.is_valid:
        raise HTTPException(
            status_code=402,
            detail=f"License is {license_.status}. Please renew your subscription."
        )

    token_data = create_license_token(user.id, user.email, license_.plan)
    return {
        "token":               token_data["token"],
        "expires_at":          token_data["expires_at"],
        "needs_refresh_after": token_data["needs_refresh_after"],
        "plan":                license_.plan,
        "email":               user.email,
    }


@router.post("/create-subscription")
def create_razorpay_subscription(req: SubscriptionRequest, db: Session = Depends(get_db)):
    """
    Create a Razorpay subscription for a user.
    Returns subscription_id and key_id for the frontend Checkout to use.
    """
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Please sign up first.")

    try:
        subscription = create_subscription(user.email, user.name, req.plan)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create subscription: {e}")

    # Store subscription ID on the license
    if user.license:
        user.license.razorpay_subscription_id = subscription["id"]
        user.license.plan = req.plan
        db.commit()

    return {
        "subscription_id": subscription["id"],
        "key_id":          os.getenv("RAZORPAY_KEY_ID", ""),
        "plan":            req.plan,
    }
