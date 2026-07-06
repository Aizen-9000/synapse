"""
synapse-auth/razorpay_handler.py

Razorpay integration for subscription billing.

Flow:
  1. Client calls /auth/create-subscription
  2. Server creates Razorpay subscription → returns subscription_id + key_id
  3. Client opens Razorpay Checkout with subscription_id
  4. User pays → Razorpay fires webhook → /webhook/razorpay
  5. Server verifies signature → activates license → issues JWT
"""

import os
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Any, Protocol

import razorpay
from dotenv import load_dotenv

# 1. Define what Razorpay's missing dynamic attributes look like
class RazorpaySubscriptionResource(Protocol):
    def create(self, data: dict[str, Any]) -> dict[str, Any]: ...
    def cancel(self, subscription_id: str, data: dict[str, Any]) -> dict[str, Any]: ...
    def fetch(self, subscription_id: str) -> dict[str, Any]: ...

class TypedRazorpayClient(Protocol):
    subscription: RazorpaySubscriptionResource 

# 2. Wire it into your initialization
_client: razorpay.Client | None = None

load_dotenv()

KEY_ID      = os.getenv("RAZORPAY_KEY_ID", "")
KEY_SECRET  = os.getenv("RAZORPAY_KEY_SECRET", "")
PLAN_BASIC  = os.getenv("PLAN_BASIC_ID", "")
PLAN_PRO    = os.getenv("PLAN_PRO_ID", "")


def get_client() -> TypedRazorpayClient:
    global _client
    if _client is None:
        if not KEY_ID or not KEY_SECRET:
            raise RuntimeError("RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET must be set in .env")
        _client = razorpay.Client(auth=(KEY_ID, KEY_SECRET))
    return _client  # type: ignore


def get_plan_id(plan: str) -> str:
    plans = {"basic": PLAN_BASIC, "pro": PLAN_PRO}
    plan_id = plans.get(plan)
    if not plan_id:
        raise ValueError(f"Unknown plan '{plan}'. Valid: basic, pro")
    return plan_id


def create_subscription(user_email: str, user_name: str, plan: str) -> dict:
    """
    Create a Razorpay subscription for a user.
    Returns the subscription object (contains id, short_url, etc.)
    """
    client  = get_client()
    plan_id = get_plan_id(plan)

    subscription = client.subscription.create({
        "plan_id":        plan_id,
        "total_count":    120,        # max months (10 years effectively)
        "quantity":       1,
        "customer_notify": 1,
        "notes": {
            "email": user_email,
            "name":  user_name,
        },
    })
    return subscription


def verify_webhook_signature(body: bytes, signature: str) -> bool:
    """
    Verify that a webhook actually came from Razorpay.
    CRITICAL: always verify before processing any webhook.
    """
    secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret:
        raise RuntimeError("RAZORPAY_WEBHOOK_SECRET not set")

    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def cancel_subscription(subscription_id: str) -> dict:
    """Cancel a Razorpay subscription (at period end by default)."""
    client = get_client()
    return client.subscription.cancel(subscription_id, {"cancel_at_cycle_end": 1})


def get_subscription(subscription_id: str) -> dict:
    """Fetch current subscription status from Razorpay."""
    client = get_client()
    return client.subscription.fetch(subscription_id)
