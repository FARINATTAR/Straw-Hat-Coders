import json
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import StreamingResponse
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

connected_clients: List[WebSocket] = []


async def broadcast(data: dict):
    for client in connected_clients[:]:
        try:
            await client.send_json(data)
        except Exception:
            connected_clients.remove(client)


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
        "markov_transitions": markov_transitions[:5],
        "stealth_score": round(stealth_score, 3),
        "evasion_indicators": evasion_indicators[:5],
        "contagion_spread": len(contagion_results),
        "credential_sharing_score": round(cred_score, 3),
        "credential_sharing_indicators": cred_indicators[:5],
        "staging_score": round(staging_score, 3),
        "staging_phase": staging_phase,
        "staging_indicators": staging_indicators[:5],
        "ghost_score": round(ghost_score, 3),
        "dormancy_days": dormancy_days,
        "ghost_indicators": ghost_indicators[:5],
        "privilege_creep_score": round(creep_score, 3),
        "privilege_sprawl_pct": sprawl_pct,
        "creep_indicators": creep_indicators[:5],
        "creep_recommendations": creep_recommendations[:5],
        "kill_chain_phase": kc_phase,
        "kill_chain_index": kc_idx,
        "kill_chain_confidence": kc_confidence,
        "kill_chain_phases": kc_phases,
        "biometric_score": round(biometric_score, 3),
        "biometric_divergence": biometric_div,
        "biometric_indicators": biometric_indicators[:3],
        "burst_score": round(burst_score, 3),
        "num_bursts": num_bursts,
        "max_burst_mb": max_burst_mb,
        "burst_indicators": burst_indicators[:3],
        "entropy_score": round(entropy_score, 3),
        "current_entropy": current_entropy,
        "baseline_entropy": baseline_entropy,
        "entropy_ratio": entropy_ratio,
        "entropy_indicators": entropy_indicators[:3],
    }


def analyze_all_users(db: Session):
    users = db.query(User).all()
    for user in users:
        analyze_user(db, user)


# ── REST API Endpoints ──────────────────────────────────────────────

@app.get("/api/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    """Main dashboard data with overview stats."""
    users = db.query(User).all()
    total_users = len(users)

    latest_scores = {}
    for user in users:
        score = (
            db.query(RiskScore)
            .filter(RiskScore.user_id == user.id)
            .order_by(desc(RiskScore.timestamp))
            .first()
        )
        if score:
            latest_scores[user.id] = score

    risk_distribution = {"green": 0, "yellow": 0, "orange": 0, "red": 0}
    for s in latest_scores.values():
        risk_distribution[s.risk_level] = risk_distribution.get(s.risk_level, 0) + 1

    total_alerts = db.query(Alert).filter(Alert.is_resolved == False).count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "critical", Alert.is_resolved == False).count()

    total_logs = db.query(ActivityLog).count()
    anomalous_logs = db.query(ActivityLog).filter(ActivityLog.is_anomalous == True).count()

    avg_risk = 0
    if latest_scores:
        avg_risk = round(sum(s.score for s in latest_scores.values()) / len(latest_scores), 1)

    ghost_count = 0
    creep_count = 0
    for user in users:
        last = ghost_account_detector.last_activity.get(user.id)
        if last and (datetime.utcnow() - last).days >= 14:
            ghost_count += 1

    return {
        "total_users": total_users,
        "risk_distribution": risk_distribution,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "total_activity_logs": total_logs,
        "anomalous_logs": anomalous_logs,
        "average_risk_score": avg_risk,
        "anomaly_rate": round(anomalous_logs / max(total_logs, 1) * 100, 1),
        "ghost_accounts": ghost_count,
        "novel_detectors_active": 12,
    }


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
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "action_type": a.action_type,
                "resource": a.resource,
                "location": a.location,
                "device": a.device,
                "data_volume_mb": a.data_volume_mb,
                "is_anomalous": a.is_anomalous,
                "anomaly_reasons": a.anomaly_reasons,
            }
            for a in activities
        ],
        "alerts": [
            {
                "id": a.id,
                "type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "timestamp": a.timestamp.isoformat(),
                "is_resolved": a.is_resolved,
            }
            for a in alerts
        ],
        "session_state": policy_engine.get_session_state(user.id),
    }


@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """Get all alerts with optional filters."""
    query = db.query(Alert).order_by(desc(Alert.timestamp))
    if severity:
        query = query.filter(Alert.severity == severity)
    if resolved is not None:
        query = query.filter(Alert.is_resolved == resolved)
    alerts = query.limit(100).all()

    return [
        {
            "id": a.id,
            "user_id": a.user_id,
            "username": a.username,
            "type": a.alert_type,
            "severity": a.severity,
            "message": a.message,
            "timestamp": a.timestamp.isoformat(),
            "is_resolved": a.is_resolved,
            "action_taken": a.action_taken,
        }
        for a in alerts
    ]


@app.get("/api/activity")
def get_activity(
    user_id: Optional[int] = None,
    anomalous_only: bool = False,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Get recent activity logs."""
    query = db.query(ActivityLog).order_by(desc(ActivityLog.timestamp))
    if user_id:
        query = query.filter(ActivityLog.user_id == user_id)
    if anomalous_only:
        query = query.filter(ActivityLog.is_anomalous == True)
    logs = query.limit(limit).all()

    return [
        {
            "id": a.id,
            "user_id": a.user_id,
            "username": a.username,
            "timestamp": a.timestamp.isoformat(),
            "action_type": a.action_type,
            "resource": a.resource,
            "location": a.location,
            "device": a.device,
            "data_volume_mb": a.data_volume_mb,
            "is_anomalous": a.is_anomalous,
            "anomaly_reasons": a.anomaly_reasons,
        }
        for a in logs
    ]


@app.get("/api/analytics")
def get_analytics(db: Session = Depends(get_db)):
    """Analytics data for charts."""
    dept_risk = {}
    users = db.query(User).all()
    for user in users:
        score = (
            db.query(RiskScore)
            .filter(RiskScore.user_id == user.id)
            .order_by(desc(RiskScore.timestamp))
            .first()
        )
        if score:
            if user.department not in dept_risk:
                dept_risk[user.department] = []
            dept_risk[user.department].append(score.score)

    dept_avg = {dept: round(sum(scores) / len(scores), 1) for dept, scores in dept_risk.items()}

    hourly_activity = {}
    logs = db.query(ActivityLog).all()
    for log in logs:
        hour = log.timestamp.hour
        if hour not in hourly_activity:
            hourly_activity[hour] = {"total": 0, "anomalous": 0}
        hourly_activity[hour]["total"] += 1
        if log.is_anomalous:
            hourly_activity[hour]["anomalous"] += 1

    hourly_data = [
        {"hour": h, "total": d["total"], "anomalous": d["anomalous"]}
        for h, d in sorted(hourly_activity.items())
    ]

    action_dist = {}
    for log in logs:
        action_dist[log.action_type] = action_dist.get(log.action_type, 0) + 1

    daily_risk = {}
    all_scores = db.query(RiskScore).order_by(RiskScore.timestamp).all()
    for s in all_scores:
        day = s.timestamp.strftime("%Y-%m-%d")
        if day not in daily_risk:
            daily_risk[day] = []
        daily_risk[day].append(s.score)

    daily_avg = [
        {"date": day, "avg_risk": round(sum(scores) / len(scores), 1), "max_risk": round(max(scores), 1)}
        for day, scores in sorted(daily_risk.items())
    ][-30:]

    top_risky = (
        db.query(RiskScore)
        .order_by(desc(RiskScore.score))
        .limit(5)
        .all()
    )
    top_risky_enriched = []
    for s in top_risky:
        u = db.query(User).filter(User.id == s.user_id).first()
        top_risky_enriched.append({
            "user_id": s.user_id,
            "username": s.username,
            "full_name": u.full_name if u else s.username,
            "department": u.department if u else "",
            "role": u.role if u else "",
            "score": s.score,
            "level": s.risk_level,
        })

    network_nodes = []
    network_links = []
    seen_users = set()
    for user in users:
        latest = db.query(RiskScore).filter(RiskScore.user_id == user.id).order_by(desc(RiskScore.timestamp)).first()
        if latest:
            network_nodes.append({
                "id": user.id, "name": user.full_name, "username": user.username,
                "department": user.department, "score": latest.score, "level": latest.risk_level,
            })
            seen_users.add(user.id)
    for uid in seen_users:
        conns = contagion_graph.get_user_connections(uid)
        for c in conns[:3]:
            if c["user_id"] in seen_users:
                link_id = tuple(sorted([uid, c["user_id"]]))
                network_links.append({
                    "source": link_id[0], "target": link_id[1],
                    "similarity": c.get("similarity", 0),
                })
    unique_links = {}
    for l in network_links:
        key = (l["source"], l["target"])
        if key not in unique_links:
            unique_links[key] = l
    network_links = list(unique_links.values())

    return {
        "department_risk": dept_avg,
        "hourly_activity": hourly_data,
        "action_distribution": action_dist,
        "daily_risk_trend": daily_avg,
        "top_risky_users": top_risky_enriched,
        "contagion_network": {"nodes": network_nodes, "links": network_links},
    }


@app.get("/api/contagion/{user_id}")
def get_contagion_graph(user_id: int, db: Session = Depends(get_db)):
    """Get risk contagion network for a user."""
    connections = contagion_graph.get_user_connections(user_id)
    enriched = []
    for conn in connections[:10]:
        neighbor = db.query(User).filter(User.id == conn["user_id"]).first()
        if neighbor:
            score = db.query(RiskScore).filter(RiskScore.user_id == conn["user_id"]).order_by(desc(RiskScore.timestamp)).first()
            enriched.append({
                "user_id": conn["user_id"],
                "username": neighbor.username,
                "full_name": neighbor.full_name,
                "department": neighbor.department,
                "similarity": conn["similarity"],
                "risk_score": score.score if score else 0,
                "risk_level": score.risk_level if score else "green",
            })
    return {"user_id": user_id, "connections": enriched}


@app.get("/api/report/{user_id}")
def generate_pdf_report(user_id: int, db: Session = Depends(get_db)):
    """Generate a professional PDF threat assessment report for a user."""
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"error": "User not found"}

    latest = db.query(RiskScore).filter(RiskScore.user_id == user_id).order_by(desc(RiskScore.timestamp)).first()
    activities = db.query(ActivityLog).filter(
        ActivityLog.user_id == user_id, ActivityLog.is_anomalous == True
    ).order_by(desc(ActivityLog.timestamp)).limit(15).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=15*mm, leftMargin=15*mm, rightMargin=15*mm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title2', parent=styles['Title'], fontSize=22, textColor=colors.HexColor('#1e293b'), spaceAfter=4)
    subtitle_style = ParagraphStyle('Sub', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#64748b'), spaceAfter=12)
    heading_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#1e40af'), spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle('Body2', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#334155'), leading=14)
    small_style = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#94a3b8'))

    elements = []

    elements.append(Paragraph("ZEROMIND THREAT ASSESSMENT", title_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | Intelligent Zero Trust Security System", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("User Profile", heading_style))
    profile_data = [
        ["Full Name", user.full_name, "Username", f"@{user.username}"],
        ["Department", user.department, "Role", user.role],
        ["Typical Login", f"{user.typical_login_hour}:00", "Location", user.typical_location],
        ["Email", user.email, "Status", "Active" if user.is_active else "Inactive"],
    ]
    profile_table = Table(profile_data, colWidths=[80, 150, 80, 150])
    profile_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
        ('TEXTCOLOR', (2, 0), (2, -1), colors.HexColor('#64748b')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (3, 0), (3, -1), colors.HexColor('#1e293b')),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
        ('FONTNAME', (3, 0), (3, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
    ]))
    elements.append(profile_table)

    elements.append(Paragraph("Risk Assessment", heading_style))
    score = latest.score if latest else 0
    level = latest.risk_level if latest else "green"
    level_color = {'red': '#dc2626', 'orange': '#ea580c', 'yellow': '#ca8a04', 'green': '#16a34a'}.get(level, '#16a34a')

    risk_data = [
        ["Risk Score", f"{score}/100"],
        ["Risk Level", level.upper()],
        ["Action Taken", latest.action_taken if latest else "Normal monitoring"],
    ]
    risk_table = Table(risk_data, colWidths=[120, 340])
    risk_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
        ('TEXTCOLOR', (1, 0), (1, 0), colors.HexColor(level_color)),
        ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (1, 0), (1, 0), 16),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor(level_color)),
        ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(risk_table)

    if latest and latest.narrative:
        elements.append(Paragraph("Threat Narrative", heading_style))
        elements.append(Paragraph(latest.narrative, body_style))

    if latest and latest.contributing_factors:
        factors = json.loads(latest.contributing_factors)
        if factors:
            elements.append(Paragraph("Contributing Factors", heading_style))
            factor_data = [["Factor", "Value", "Contribution", "Weight"]]
            for f in factors[:12]:
                factor_data.append([
                    f.get("factor", "")[:50],
                    str(f.get("value", "")),
                    f"{f.get('contribution', 0)}%",
                    str(f.get("weight", "")),
                ])
            factor_table = Table(factor_data, colWidths=[220, 60, 80, 60])
            factor_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ]))
            elements.append(factor_table)

    if activities:
        elements.append(Paragraph("Recent Anomalous Activities", heading_style))
        act_data = [["Time", "Action", "Resource", "Volume (MB)"]]
        for a in activities[:10]:
            act_data.append([
                a.timestamp.strftime('%m/%d %H:%M'),
                a.action_type,
                (a.resource or "")[:30],
                f"{a.data_volume_mb:.1f}" if a.data_volume_mb > 0 else "-",
            ])
        act_table = Table(act_data, colWidths=[80, 80, 200, 70])
        act_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fef2f2')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(act_table)

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))
    elements.append(Paragraph("ZeroMind | Intelligent Zero Trust Security System | 12 AI Detection Engines | Straw Hat Coders", small_style))

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=zeromind_report_{user.username}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"}
    )


@app.get("/api/coordinated_attacks")
def get_coordinated_attacks():
    """Check for coordinated attack patterns across users."""
    is_coord, score, users, indicators = coordinated_attack_detector.detect()
    return {
        "is_coordinated": is_coord,
        "coordination_score": score,
        "correlated_users": [{"user_id": u["user_id"], "username": u["username"], "score": u["score"]} for u in users[:10]],
        "indicators": indicators,
        "total_risk_events": len(coordinated_attack_detector.risk_events),
    }


@app.post("/api/simulate/{scenario}")
async def simulate_scenario(scenario: str, db: Session = Depends(get_db)):
    """Trigger a live demo scenario and broadcast results via WebSocket."""
    from data_generator import (
        inject_anomalies_data_exfiltrator,
        inject_anomalies_compromised_account,
        inject_anomalies_slow_insider,
        inject_credential_sharing,
        inject_data_staging,
        inject_ghost_account,
        inject_privilege_creep,
        inject_kill_chain,
        inject_biometric_shift,
        inject_coordinated_attack,
        inject_micro_burst,
        inject_entropy_spike,
    )

    now = datetime.utcnow()
    result = None

    if scenario == "data_exfiltrator":
        user = db.query(User).filter(User.username == "bob.johnson").first()
        if user:
            inject_anomalies_data_exfiltrator(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "compromised_account":
        user = db.query(User).filter(User.username == "eve.jones").first()
        if user:
            inject_anomalies_compromised_account(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "slow_insider":
        user = db.query(User).filter(User.username == "henry.davis").first()
        if user:
            inject_anomalies_slow_insider(db, user, now)
            result = analyze_user(db, user, window_hours=200)
    elif scenario == "credential_sharing":
        user = db.query(User).filter(User.username == "charlie.williams").first()
        if user:
            inject_credential_sharing(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "data_staging":
        user = db.query(User).filter(User.username == "diana.brown").first()
        if user:
            inject_data_staging(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "ghost_account":
        user = db.query(User).filter(User.username == "ivy.rodriguez").first()
        if user:
            inject_ghost_account(db, user, now)
            ghost_account_detector.last_activity[user.id] = now - timedelta(days=25)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "privilege_creep":
        user = db.query(User).filter(User.username == "jack.martinez").first()
        if user:
            inject_privilege_creep(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "kill_chain":
        user = db.query(User).filter(User.username == "nathan.wilson").first()
        if user:
            inject_kill_chain(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "biometric_shift":
        user = db.query(User).filter(User.username == "olivia.anderson").first()
        if user:
            inject_biometric_shift(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "coordinated_attack":
        inject_coordinated_attack(db, now)
        results_list = []
        for uname in ["karen.hernandez", "leo.lopez", "mona.gonzalez"]:
            u = db.query(User).filter(User.username == uname).first()
            if u:
                r = analyze_user(db, u, window_hours=24)
                if r:
                    results_list.append(r)
                    await broadcast({"type": "risk_update", "data": r})
        is_coord, coord_score, coord_users, coord_indicators = coordinated_attack_detector.detect()
        coord_result = {
            "scenario": "coordinated_attack",
            "coordination_detected": is_coord,
            "coordination_score": coord_score,
            "users_compromised": len(results_list),
            "indicators": coord_indicators,
            "user_results": results_list,
            "risk_score": max((r["risk_score"] for r in results_list), default=0),
            "risk_level": "red" if is_coord else "orange",
            "narrative": "; ".join(coord_indicators) if coord_indicators else "Coordinated attack simulation executed",
            "session_state": "terminated",
            "policy_actions": ["Session terminated for all compromised accounts"],
        }
        await broadcast({"type": "alert", "data": {
            "username": "MULTI-USER",
            "risk_score": coord_result["risk_score"],
            "risk_level": coord_result["risk_level"],
            "narrative": coord_result["narrative"],
            "actions": coord_result["policy_actions"],
        }})
        return coord_result
    elif scenario == "micro_burst":
        user = db.query(User).filter(User.username == "paul.thomas").first()
        if user:
            inject_micro_burst(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    elif scenario == "entropy_spike":
        user = db.query(User).filter(User.username == "quinn.taylor").first()
        if user:
            inject_entropy_spike(db, user, now)
            result = analyze_user(db, user, window_hours=24)
    else:
        return {"error": f"Unknown scenario: {scenario}"}

    if result:
        await broadcast({"type": "risk_update", "data": result})
        await broadcast({
            "type": "alert",
            "data": {
                "username": result["username"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "narrative": result["narrative"],
                "actions": result["policy_actions"],
            },
        })
    return result or {"error": "User not found for scenario"}


@app.post("/api/analyze")
async def trigger_analysis(db: Session = Depends(get_db)):
    """Re-run analysis on all users."""
    users = db.query(User).all()
    results = []
    for user in users:
        result = analyze_user(db, user)
        if result:
            results.append(result)
            await broadcast({"type": "risk_update", "data": result})
    return {"analyzed": len(results)}


# ── WebSocket ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


@app.get("/api/dashboard/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Lightweight endpoint for high-level dashboard metrics."""
    return {
        "active_monitors": 12,
        "system_status": "healthy",
        "last_refresh": datetime.utcnow().isoformat(),
        "total_users_scored": db.query(User).count()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
