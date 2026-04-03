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
from data_generator import generate_all_data
from ml_engine import ml_engine
from risk_engine import risk_engine
from policy_engine import policy_engine
from novel_engines import (
    markov_chain, contagion_graph, evasion_detector,
    credential_sharing_detector, data_staging_detector,
    ghost_account_detector, privilege_creep_detector,
    kill_chain_detector, biometric_detector, coordinated_attack_detector,
    micro_burst_detector, entropy_monitor,
)
from config import RISK_THRESHOLDS, HONEYPOT_RESOURCES


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing ZeroMind...")
    init_db()
    generate_all_data()
    db = SessionLocal()
    try:
        ml_engine.train(db)
        train_novel_engines(db)
        analyze_all_users(db)
    finally:
        db.close()
    print("ZeroMind ready!")
    yield


app = FastAPI(title="ZeroMind - Zero Trust Security System", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def train_novel_engines(db):
    """Train all 12 novel engines."""
    users = db.query(User).all()
    cutoff = datetime.utcnow() - timedelta(days=35)
    all_normal = []
    users_activities = {}

    for user in users:
        activities = (
            db.query(ActivityLog)
            .filter(ActivityLog.user_id == user.id, ActivityLog.is_anomalous == False, ActivityLog.timestamp >= cutoff)
            .order_by(ActivityLog.timestamp).all()
        )
        if activities:
            markov_chain.train_user(user.id, activities)
            users_activities[user.id] = activities
            all_normal.extend(activities)

            unique_resources = set(a.resource for a in activities if a.action_type in ("file_access", "download", "api_call"))
            days_span = max((activities[-1].timestamp - activities[0].timestamp).days, 1)
            data_staging_detector.set_baseline(user.id, len(unique_resources) / days_span, {user.department})

            if activities:
                ghost_account_detector.update_last_activity(user.id, activities[-1].timestamp)

        profile = ml_engine.user_profiles.get(user.id)
        if profile:
            evasion_detector.set_user_thresholds(
                user.id, profile["mean_data_volume"], profile["std_data_volume"]
            )

        if activities:
            biometric_detector.train_user(user.id, activities)
            entropy_monitor.train_user(user.id, activities)

            volumes = [a.data_volume_mb for a in activities if a.data_volume_mb > 0]
            if volumes:
                span_min = max((activities[-1].timestamp - activities[0].timestamp).total_seconds() / 60, 1)
                micro_burst_detector.set_baseline(user.id, sum(volumes) / span_min)

    if all_normal:
        markov_chain.train_global(all_normal)
    contagion_graph.build_graph(users_activities)
    privilege_creep_detector.build_role_matrix()
    print(f"12 Novel engines trained: Markov({len(markov_chain.user_chains)}), "
          f"Contagion({len(contagion_graph.adjacency)}), Evasion, CredSharing, "
          f"DataStaging({len(data_staging_detector.user_baselines)}), "
          f"Ghost({len(ghost_account_detector.last_activity)}), PrivCreep, "
          f"KillChain, Biometric({len(biometric_detector.user_profiles)}), "
          f"CoordAttack, MicroBurst({len(micro_burst_detector.user_baselines)}), "
          f"Entropy({len(entropy_monitor.user_baselines)})")


def analyze_user(db: Session, user: User, window_hours: int = 24):
    """Run full analysis pipeline for a single user."""
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    activities = (
        db.query(ActivityLog)
        .filter(ActivityLog.user_id == user.id, ActivityLog.timestamp >= cutoff)
        .order_by(ActivityLog.timestamp)
        .all()
    )

    if not activities:
        return None

    is_anomaly, anomaly_score, feature_scores = ml_engine.predict_anomaly(user.id, activities)
    is_anomaly = bool(is_anomaly)
    anomaly_score = float(anomaly_score)
    feature_scores = {k: float(v) for k, v in feature_scores.items()}
    peer_score, peer_deviations = ml_engine.get_peer_deviation(user.id, user.department, activities)

    markov_score, markov_transitions = markov_chain.score_sequence(user.id, activities)
    stealth_score, evasion_indicators = evasion_detector.detect_evasion(user.id, activities)
    cred_score, cred_indicators = credential_sharing_detector.detect(activities)
    staging_score, staging_indicators, staging_phase = data_staging_detector.detect(user.id, activities, user.department)
    ghost_score, dormancy_days, ghost_indicators = ghost_account_detector.detect(user.id, activities)
    creep_score, sprawl_pct, creep_indicators, creep_recommendations = privilege_creep_detector.detect(user.id, user.department, activities)

    biometric_score, biometric_div, biometric_indicators = biometric_detector.detect(user.id, activities)
    burst_score, num_bursts, max_burst_mb, burst_indicators = micro_burst_detector.detect(user.id, activities)
    entropy_score, current_entropy, baseline_entropy, entropy_ratio, entropy_indicators = entropy_monitor.detect(user.id, activities)

    novel_boost = (markov_score * 0.10) + (stealth_score * 0.06) + (cred_score * 0.12) + \
                  (staging_score * 0.10) + (ghost_score * 0.12) + (creep_score * 0.06) + \
                  (biometric_score * 0.08) + (burst_score * 0.10) + (entropy_score * 0.06)
    anomaly_score = min(1.0, anomaly_score + novel_boost)

    if markov_transitions:
        for t in markov_transitions[:2]:
            peer_deviations.append(f"Sequence anomaly: {t}")
    if evasion_indicators:
        for e in evasion_indicators[:2]:
            peer_deviations.append(f"Evasion: {e}")
    if cred_indicators:
        for c in cred_indicators[:2]:
            peer_deviations.append(f"Credential Sharing: {c}")
    if staging_indicators:
        for s in staging_indicators[:2]:
            peer_deviations.append(f"Data Staging: {s}")
    if ghost_indicators:
        for g in ghost_indicators[:2]:
            peer_deviations.append(f"Ghost Account: {g}")
    if creep_indicators:
        for ci in creep_indicators[:2]:
            peer_deviations.append(f"Privilege Creep: {ci}")
    if biometric_indicators:
        for bi in biometric_indicators[:2]:
            peer_deviations.append(f"Biometric: {bi}")
    if burst_indicators:
        for bu in burst_indicators[:2]:
            peer_deviations.append(f"Micro-Burst: {bu}")
    if entropy_indicators:
        for ei in entropy_indicators[:2]:
            peer_deviations.append(f"Entropy: {ei}")

    score = risk_engine.calculate_risk_score(user.id, anomaly_score, feature_scores, peer_score, peer_deviations)
    level = risk_engine.get_risk_level(score)
    action = risk_engine.get_action(level)
    narrative = risk_engine.generate_narrative(user.username, score, level, feature_scores, peer_deviations, activities)
    factors = risk_engine.generate_contributing_factors(feature_scores, peer_deviations)

    if markov_score > 0.3:
        factors.append({"factor": "Action sequence anomaly (Markov Chain)", "value": round(markov_score, 2), "contribution": round(markov_score * 25, 1), "weight": 0.12})
    if stealth_score > 0.2:
        factors.append({"factor": "Adversarial evasion detected (Stealth Score)", "value": round(stealth_score, 2), "contribution": round(stealth_score * 20, 1), "weight": 0.08})
    if cred_score > 0.2:
        factors.append({"factor": "Credential sharing / session cloning", "value": round(cred_score, 2), "contribution": round(cred_score * 30, 1), "weight": 0.15})
    if staging_score > 0.2:
        factors.append({"factor": f"Data staging detected ({staging_phase})", "value": round(staging_score, 2), "contribution": round(staging_score * 25, 1), "weight": 0.12})
    if ghost_score > 0.1:
        factors.append({"factor": f"Ghost account resurrection ({dormancy_days}d dormant)", "value": round(ghost_score, 2), "contribution": round(ghost_score * 30, 1), "weight": 0.15})
    if creep_score > 0.2:
        factors.append({"factor": f"Privilege creep ({sprawl_pct:.0f}% outside role)", "value": round(creep_score, 2), "contribution": round(creep_score * 20, 1), "weight": 0.06})
    if biometric_score > 0.2:
        factors.append({"factor": f"Behavioral biometric shift (KL={biometric_div:.2f})", "value": round(biometric_score, 2), "contribution": round(biometric_score * 20, 1), "weight": 0.08})
    if burst_score > 0.2:
        factors.append({"factor": f"Micro-burst exfiltration ({num_bursts} bursts, peak {max_burst_mb}MB)", "value": round(burst_score, 2), "contribution": round(burst_score * 25, 1), "weight": 0.10})
    if entropy_score > 0.1:
        factors.append({"factor": f"Access entropy spike ({entropy_ratio:.1f}x baseline)", "value": round(entropy_score, 2), "contribution": round(entropy_score * 15, 1), "weight": 0.06})

    kc_phase, kc_idx, kc_confidence, kc_phases = kill_chain_detector.detect(
        user.id, activities, user.department,
        staging_score=staging_score, creep_score=creep_score, cred_score=cred_score,
        markov_score=markov_score, stealth_score=stealth_score, ghost_score=ghost_score,
    )
    if kc_idx >= 0:
        factors.append({"factor": f"Kill Chain: {kc_phase} phase ({kc_confidence:.0%} confidence)", "value": round(kc_confidence, 2), "contribution": round(kc_confidence * 20, 1), "weight": 0.10})

    actions, alerts = policy_engine.evaluate_session(user.id, user.username, score, level, feature_scores)

    contagion_results = {}
    if score >= 60:
        contagion_results = contagion_graph.propagate_risk(user.id, score)

    risk_record = RiskScore(
        user_id=user.id, username=user.username,
        score=score, risk_level=level, timestamp=datetime.utcnow(),
        contributing_factors=json.dumps(factors),
        action_taken=action, narrative=narrative,
    )
    db.add(risk_record)

    for alert in alerts:
        db.add(alert)

    if contagion_results:
        for neighbor_id, (c_score, c_reason) in contagion_results.items():
            neighbor = db.query(User).filter(User.id == neighbor_id).first()
            if neighbor:
                db.add(Alert(
                    user_id=neighbor_id, username=neighbor.username,
                    alert_type="contagion", severity="medium",
                    message=c_reason, timestamp=datetime.utcnow(),
                    is_resolved=False, action_taken="Enhanced monitoring",
                ))

    db.commit()

    if score >= 50:
        coordinated_attack_detector.record_risk_event(user.id, user.username, score, datetime.utcnow())

    return {
        "user_id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "department": user.department,
        "role": user.role,
        "risk_score": score,
        "risk_level": level,
        "action_taken": action,
        "narrative": narrative,
        "contributing_factors": factors,
        "policy_actions": actions,
        "is_anomaly": is_anomaly,
        "session_state": policy_engine.get_session_state(user.id),
        "activity_count": len(activities),
        "markov_score": round(markov_score, 3),
        "stealth_score": round(stealth_score, 3),
        "credential_sharing_score": round(cred_score, 3),
        "staging_score": round(staging_score, 3),
        "ghost_score": round(ghost_score, 3),
        "privilege_creep_score": round(creep_score, 3),
        "biometric_score": round(biometric_score, 3),
        "burst_score": round(burst_score, 3),
        "entropy_score": round(entropy_score, 3),
    }


def analyze_all_users(db: Session):
    users = db.query(User).all()
    for user in users:
        analyze_user(db, user)


# ── REST API Endpoints ──────────────────────────────────────────────

@app.get("/api/users")
def get_users(db: Session = Depends(get_db)):
    """Get all users with their latest risk scores."""
    users = db.query(User).all()
    result = []
    for user in users:
        score = (
            db.query(RiskScore)
            .filter(RiskScore.user_id == user.id)
            .order_by(desc(RiskScore.timestamp))
            .first()
        )
        result.append({
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "department": user.department,
            "role": user.role,
            "is_active": user.is_active,
            "risk_score": score.score if score else 0,
            "risk_level": score.risk_level if score else "green",
            "narrative": score.narrative if score else "",
            "session_state": policy_engine.get_session_state(user.id),
        })
    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result


@app.get("/api/users/{user_id}")
def get_user_detail(user_id: int, db: Session = Depends(get_db)):
    """Detailed user view with risk history and activities."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"error": "User not found"}

    scores = (
        db.query(RiskScore)
        .filter(RiskScore.user_id == user_id)
        .order_by(desc(RiskScore.timestamp))
        .limit(50)
        .all()
    )

    latest = scores[0] if scores else None

    activities = (
        db.query(ActivityLog)
        .filter(ActivityLog.user_id == user_id)
        .order_by(desc(ActivityLog.timestamp))
        .limit(100)
        .all()
    )

    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == user_id)
        .order_by(desc(Alert.timestamp))
        .limit(20)
        .all()
    )

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "department": user.department,
            "role": user.role,
            "typical_login_hour": user.typical_login_hour,
            "typical_location": user.typical_location,
        },
        "current_risk": {
            "score": latest.score if latest else 0,
            "level": latest.risk_level if latest else "green",
            "narrative": latest.narrative if latest else "",
            "contributing_factors": json.loads(latest.contributing_factors) if latest and latest.contributing_factors else [],
            "action_taken": latest.action_taken if latest else "Normal monitoring",
        },
        "risk_history": [
            {"score": s.score, "level": s.risk_level, "timestamp": s.timestamp.isoformat(), "action": s.action_taken}
            for s in scores
        ],
        "recent_activities": [
            {
                "id": a.id, "timestamp": a.timestamp.isoformat(), "action_type": a.action_type,
                "resource": a.resource, "location": a.location, "device": a.device,
                "data_volume_mb": a.data_volume_mb, "is_anomalous": a.is_anomalous,
            }
            for a in activities
        ],
        "alerts": [
            {"id": a.id, "type": a.alert_type, "severity": a.severity, "message": a.message, "timestamp": a.timestamp.isoformat(), "is_resolved": a.is_resolved}
            for a in alerts
        ],
        "session_state": policy_engine.get_session_state(user.id),
    }


@app.get("/api/alerts")
def get_alerts(severity: Optional[str] = None, resolved: Optional[bool] = None, db: Session = Depends(get_db)):
    """Get all alerts with optional filters."""
    query = db.query(Alert).order_by(desc(Alert.timestamp))
    if severity:
        query = query.filter(Alert.severity == severity)
    if resolved is not None:
        query = query.filter(Alert.is_resolved == resolved)
    alerts = query.limit(100).all()

    return [
        {"id": a.id, "user_id": a.user_id, "username": a.username, "type": a.alert_type, "severity": a.severity,
         "message": a.message, "timestamp": a.timestamp.isoformat(), "is_resolved": a.is_resolved, "action_taken": a.action_taken}
        for a in alerts
    ]


@app.get("/api/activity")
def get_activity(user_id: Optional[int] = None, anomalous_only: bool = False, limit: int = 50, db: Session = Depends(get_db)):
    """Get recent activity logs."""
    query = db.query(ActivityLog).order_by(desc(ActivityLog.timestamp))
    if user_id:
        query = query.filter(ActivityLog.user_id == user_id)
    if anomalous_only:
        query = query.filter(ActivityLog.is_anomalous == True)
    logs = query.limit(limit).all()

    return [
        {"id": a.id, "user_id": a.user_id, "username": a.username, "timestamp": a.timestamp.isoformat(),
         "action_type": a.action_type, "resource": a.resource, "location": a.location, "device": a.device,
         "data_volume_mb": a.data_volume_mb, "is_anomalous": a.is_anomalous}
        for a in logs
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
