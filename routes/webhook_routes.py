"""
synapse-auth/routes/webhook_routes.py

POST /webhook/razorpay

This is the most critical route. Razorpay fires events here when:
  - subscription.charged      → payment succeeded → activate license
  - subscription.halted       → payment failed repeatedly → suspend license
  - subscription.cancelled    → user cancelled → mark cancelled
  - subscription.completed    → subscription ended → expire license
  - payment.failed            → single payment failed (may retry)

ALWAYS verify the webhook signature before processing.
"""

import json
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import License, RevokedToken
from auth import create_license_token
from razorpay_handler import verify_webhook_signature

router = APIRouter(prefix="/webhook", tags=["webhook"])

# How long a charged subscription is valid
BILLING_CYCLE_DAYS = int(os.getenv("BILLING_CYCLE_DAYS", "31"))


@router.post("/razorpay")
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    body      = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")

    # ── Step 1: Verify signature ───────────────────────────────────────────────
    try:
        if not verify_webhook_signature(body, signature):
            raise HTTPException(status_code=400, detail="Invalid webhook signature")
    except RuntimeError as e:
        # RAZORPAY_WEBHOOK_SECRET not set — log and accept in dev, reject in prod
        if os.getenv("ENV", "development") == "production":
            raise HTTPException(status_code=500, detail=str(e))

    # ── Step 2: Parse event ────────────────────────────────────────────────────
    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event_type    = event.get("event", "")
    payload_data  = event.get("payload", {})

    # Extract subscription from payload
    subscription_data = (
        payload_data.get("subscription", {}).get("entity", {})
        or payload_data.get("payment", {}).get("entity", {})
    )
    subscription_id = subscription_data.get("subscription_id") or subscription_data.get("id")

    if not subscription_id:
        # Not a subscription event we care about
        return {"status": "ignored", "event": event_type}

    # ── Step 3: Find license by subscription ID ────────────────────────────────
    license_ = db.query(License).filter(
        License.razorpay_subscription_id == subscription_id
    ).first()

    if not license_:
        # Unknown subscription — log but don't fail (could be a test)
        return {"status": "not_found", "subscription_id": subscription_id}

    # ── Step 4: Handle event ───────────────────────────────────────────────────

    if event_type == "subscription.charged":
        # Payment succeeded — activate or extend license
        license_.status      = "active"
        license_.activated_at = license_.activated_at or datetime.utcnow()
        license_.expires_at  = datetime.utcnow() + timedelta(days=BILLING_CYCLE_DAYS)
        license_.cancelled_at = None
        db.commit()

        # Optionally: generate and email a fresh token to the user here
        # token_data = create_license_token(license_.user.id, license_.user.email, license_.plan)
        # send_license_email(license_.user.email, token_data["token"])

        # 1. Pull the value out first
        expires_dt = license_.expires_at

        # 2. Pylance now understands this guard statement perfectly
        expires_str = expires_dt.isoformat() if expires_dt is not None else None

        return {
           "status": "activated", 
           "expires_at": expires_str
        }

    elif event_type in ("subscription.halted", "subscription.cancelled", "subscription.completed"):
        # Payment failed or user cancelled — suspend license
        new_status = {
            "subscription.halted":    "expired",
            "subscription.cancelled": "cancelled",
            "subscription.completed": "expired",
        }[event_type]

        license_.status       = new_status
        license_.cancelled_at = datetime.utcnow() if event_type == "subscription.cancelled" else None

        # Revoke ALL active tokens for this user immediately
        # (next client validation check will fail, client will lock)
        _revoke_all_user_tokens(license_.user_id, f"license_{new_status}", db)

        db.commit()
        return {"status": new_status}

    elif event_type == "payment.failed":
        # Single payment failed — don't suspend yet (Razorpay will retry)
        # Just log it. If it keeps failing, subscription.halted will fire.
        return {"status": "payment_failed_acknowledged"}

    return {"status": "unhandled", "event": event_type}


def _revoke_all_user_tokens(user_id: str, reason: str, db: Session):
    """
    We can't enumerate all issued JWTs, but we can add a sentinel record.
    Any token with iat before this timestamp for this user gets rejected.

    Simpler approach used here: add the user_id to a user-level blocklist
    by inserting a special 'all_before' record. The validate endpoint checks it.

    For now, we rely on: client calls /license/validate every 24h.
    When license.is_valid returns False, client locks itself within 24h.
    """
    # Mark user-level revocation with a wildcard JTI
    sentinel = RevokedToken(
        jti=f"ALL_{user_id}",
        user_id=user_id,
        reason=reason,
    )
    # Upsert
    existing = db.query(RevokedToken).filter(
        RevokedToken.jti == sentinel.jti
    ).first()
    if not existing:
        db.add(sentinel)
