"""Environment-driven configuration and database session management."""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get("SENTINEL_DATABASE_URL", "sqlite:///sentinel.db")
SNAPSHOT_CSV_PATH = os.environ.get("SENTINEL_SNAPSHOT_CSV", "safety_evaluation_snapshot.csv")
DAEMON_POLL_INTERVAL_SECONDS = float(os.environ.get("SENTINEL_POLL_INTERVAL", "5"))

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, future=True)


def get_session():
    return SessionLocal()
