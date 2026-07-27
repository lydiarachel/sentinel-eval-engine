"""ORM schemas for the mock model transaction log and safety findings."""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class ModelPrompt(Base):
    __tablename__ = "model_prompts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    prompt_text = Column(Text, nullable=False)
    response_text = Column(Text, nullable=False)
    model_version = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def __repr__(self):
        return f"<ModelPrompt id={self.id} model={self.model_version}>"


class SafetyFinding(Base):
    __tablename__ = "safety_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    prompt_id = Column(Integer, nullable=False, index=True)
    rule_id = Column(String(16), nullable=False, index=True)
    severity = Column(String(16), nullable=False)
    error_detail = Column(Text, nullable=False)
    record_payload = Column(Text, nullable=False)
    detected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def __repr__(self):
        return f"<SafetyFinding rule={self.rule_id} prompt={self.prompt_id}>"


def init_db(engine):
    Base.metadata.create_all(engine)
