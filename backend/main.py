import json
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from models import init_db, get_db, SessionLocal, User, ActivityLog, RiskScore, Alert
from config import RISK_THRESHOLDS, HONEYPOT_RESOURCES

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing ZeroMind API Infrastructure...")
    init_db()
    # Initial data analysis will be integrated in next stage
    yield
    print("Shutting down...")

app = FastAPI(title="ZeroMind - Zero Trust Security System", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Basic REST Endpoints ---

@app.get("/")
def read_root():
    return {"message": "ZeroMind API Core Online", "status": "Infrastructure_Ready"}

@app.get("/api/users")
def get_users(db: Session = Depends(get_db)):
    """Basic user listing."""
    users = db.query(User).all()
    result = []
    for user in users:
        score = db.query(RiskScore).filter(RiskScore.user_id == user.id).order_by(desc(RiskScore.timestamp)).first()
        result.append({
            "id": user.id,
            "username": user.username,
            "department": user.department,
            "risk_score": score.score if score else 0,
            "risk_level": score.risk_level if score else "green"
        })
    return result

@app.get("/api/alerts")
def get_alerts(db: Session = Depends(get_db)):
    """Fetch recent security alerts."""
    alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(50).all()
    return alerts

@app.get("/api/activity")
def get_activity(limit: int = 50, db: Session = Depends(get_db)):
    """Monitor recent activity logs."""
    logs = db.query(ActivityLog).order_by(desc(ActivityLog.timestamp)).limit(limit).all()
    return logs

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
