from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB
from uuid import uuid4

class Base(DeclarativeBase):
    pass

class StudentSession(Base):
    __tablename__ = "student_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    display_name: Mapped[str] = mapped_column(String(64))
    variant: Mapped[str] = mapped_column(String(1))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[object] = mapped_column(DateTime(timezone=True))

class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scenario_slug: Mapped[str] = mapped_column(String(80), index=True)
    variant: Mapped[str] = mapped_column(String(1), index=True)
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    host_name: Mapped[str] = mapped_column(String(64), index=True)
    event_code: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    provider: Mapped[str] = mapped_column(String(120))
    object_key: Mapped[str] = mapped_column(String(512), index=True)
    service_name: Mapped[str | None] = mapped_column(String(200), index=True, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(200), index=True, nullable=True)
    registry_key: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    normalized: Mapped[dict] = mapped_column(JSONB)
    raw: Mapped[dict] = mapped_column(JSONB)
    search_text: Mapped[str] = mapped_column(Text)
    provenance: Mapped[str] = mapped_column(String(40), default="generated")

    __table_args__ = (Index("ix_events_scenario_variant_timestamp", "scenario_slug", "variant", "timestamp"),)

class ScenarioSeed(Base):
    __tablename__ = "scenario_seeds"
    id: Mapped[str] = mapped_column(String(170), primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    event_count: Mapped[int] = mapped_column(Integer)
    seeded_at: Mapped[object] = mapped_column(DateTime(timezone=True))

class EvidenceSelection(Base):
    __tablename__ = "evidence_selections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    student_id: Mapped[str] = mapped_column(ForeignKey("student_sessions.id", ondelete="CASCADE"), index=True)
    scenario_slug: Mapped[str] = mapped_column(String(80))
    delta_id: Mapped[str] = mapped_column(String(80))
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"))
    selected_at: Mapped[object] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("student_id", "scenario_slug", "delta_id", "event_id"),)

class Submission(Base):
    __tablename__ = "submissions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    student_id: Mapped[str] = mapped_column(ForeignKey("student_sessions.id", ondelete="CASCADE"), index=True)
    scenario_slug: Mapped[str] = mapped_column(String(80), index=True)
    delta_id: Mapped[str] = mapped_column(String(80))
    classification: Mapped[str] = mapped_column(String(32))
    explanation: Mapped[str] = mapped_column(Text)
    submitted_at: Mapped[object] = mapped_column(DateTime(timezone=True))
    score: Mapped[int] = mapped_column(Integer)
    correct: Mapped[bool] = mapped_column(Boolean)
    evidence_ids: Mapped[list] = mapped_column(JSONB)
    __table_args__ = (UniqueConstraint("student_id", "scenario_slug", "delta_id"),)

class SearchHistory(Base):
    __tablename__ = "search_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    student_id: Mapped[str] = mapped_column(ForeignKey("student_sessions.id", ondelete="CASCADE"), index=True)
    scenario_slug: Mapped[str] = mapped_column(String(80))
    query: Mapped[str] = mapped_column(String(500))
    result_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True))

class LabControl(Base):
    __tablename__ = "lab_control"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    mode: Mapped[str] = mapped_column(String(16), default="challenge")
    enabled_cases: Mapped[list] = mapped_column(JSON, default=list)
