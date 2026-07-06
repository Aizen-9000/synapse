"""
synapse-auth/database.py

Handles both:
  - SQLite locally (DATABASE_URL=sqlite:///./synapse_auth.db)
  - PostgreSQL on Render (DATABASE_URL=postgresql://... set automatically via render.yaml)
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./synapse_auth.db")

# Render sets DATABASE_URL starting with "postgres://" (older format)
# SQLAlchemy 2.x requires "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLite needs check_same_thread=False; PostgreSQL doesn't accept it
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from synapse_auth import models  # noqa
    Base.metadata.create_all(bind=engine)
