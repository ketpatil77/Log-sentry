import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./logsentry.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class Analysis(Base):
    __tablename__ = "analyses"
    id = Column(String, primary_key=True)
    filename = Column(String(255), nullable=False)
    log_type = Column(String(64), nullable=False)
    events_processed = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False)
    incidents = relationship("Incident", cascade="all, delete-orphan", back_populates="analysis")

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    analysis_id = Column(String, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    attack_type = Column(String(128), nullable=False)
    source_ip = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    risk_score = Column(Integer, nullable=False)
    event_count = Column(Integer, nullable=False)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    mitre_id = Column(String(32), nullable=False)
    mitre_name = Column(String(128), nullable=False)
    recommendation = Column(Text, nullable=False)
    analysis = relationship("Analysis", back_populates="incidents")
    evidence = relationship("Evidence", cascade="all, delete-orphan", back_populates="incident")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    raw_log = Column(Text, nullable=False)
    timestamp = Column(DateTime)
    incident = relationship("Incident", back_populates="evidence")

def init_db():
    Base.metadata.create_all(bind=engine)
