"""
synapse-auth/models.py

Three tables:
  users         — account credentials
  licenses      — subscription status per user
  revoked_tokens — JTI blocklist for invalidating tokens immediately
"""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id:           Mapped[str]      = mapped_column(String, primary_key=True, default=_uuid)
    email:        Mapped[str]      = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash:Mapped[str]      = mapped_column(String, nullable=False)
    name:         Mapped[str]      = mapped_column(String, default="")
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active:    Mapped[bool]     = mapped_column(Boolean, default=True)

    license: Mapped["License"] = relationship("License", back_populates="user", uselist=False)


class License(Base):
    __tablename__ = "licenses"

    id:                     Mapped[str]           = mapped_column(String, primary_key=True, default=_uuid)
    user_id:                Mapped[str]           = mapped_column(String, ForeignKey("users.id"), unique=True)
    plan:                   Mapped[str]           = mapped_column(String, default="basic")  # basic | pro
    status:                 Mapped[str]           = mapped_column(String, default="pending")
    # Status values:
    #   pending    — awaiting first payment
    #   active     — subscription is current
    #   cancelled  — user cancelled
    #   expired    — payment failed, grace period over
    #   suspended  — manually suspended

    razorpay_subscription_id: Mapped[str | None]  = mapped_column(String, nullable=True)
    razorpay_customer_id:     Mapped[str | None]  = mapped_column(String, nullable=True)

    activated_at:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at:    Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancelled_at:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at:    Mapped[datetime]        = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="license")

    @property
    def is_valid(self) -> bool:
        if self.status != "active":
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti:        Mapped[str]      = mapped_column(String, primary_key=True)
    user_id:    Mapped[str]      = mapped_column(String, index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reason:     Mapped[str]      = mapped_column(String, default="")
