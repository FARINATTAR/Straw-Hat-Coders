from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)
    email = Column(String)
    department = Column(String)
    role = Column(String)
    typical_login_hour = Column(Integer, default=9)
    typical_location = Column(String, default="New York, US")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action_type = Column(String)  # login, logout, file_access, download, api_call, failed_login
    resource = Column(String)
    ip_address = Column(String)
    location = Column(String)
    device = Column(String)
    data_volume_mb = Column(Float, default=0.0)
    session_duration_min = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    anomaly_reasons = Column(Text, default="")


class RiskScore(Base):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String, index=True)
    score = Column(Float, default=0.0)
    risk_level = Column(String, default="green")
    timestamp = Column(DateTime, default=datetime.utcnow)
    contributing_factors = Column(Text, default="")
    action_taken = Column(String, default="Normal monitoring")
    narrative = Column(Text, default="")


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String)
    alert_type = Column(String)  # anomaly, honeypot, risk_threshold, peer_deviation
    severity = Column(String)  # low, medium, high, critical
    message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False)
    action_taken = Column(String, default="")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
