from datetime import datetime, timedelta
from collections import defaultdict
from models import SessionLocal, RiskScore, Alert, ActivityLog, User
from config import RISK_THRESHOLDS, RISK_ACTIONS, HONEYPOT_RESOURCES


class RiskEngine:
    """Dynamic risk scoring with decay, compounding, and explainable narratives."""

    def __init__(self):
        self.user_risk_history = defaultdict(list)
        self.risk_decay_rate = 0.05
        self.risk_compound_rate = 1.3

    def calculate_risk_score(self, user_id, anomaly_score, feature_scores, peer_score, peer_deviations):
        """Calculate dynamic risk score with decay and compounding."""
        base_score = anomaly_score * 70

        if feature_scores.get("honeypot_access_count", 0) > 0:
            base_score = max(base_score, 90)

        base_score += peer_score * 20

        if feature_scores.get("failed_login_count", 0) > 2:
            base_score += 10
        if feature_scores.get("anomalous_location_count", 0) > 0:
            base_score += 10
        if feature_scores.get("off_hours_activity_count", 0) > 3:
            base_score += 5

        recent_scores = self.user_risk_history.get(user_id, [])

        if len(recent_scores) > 0:
            last_score = recent_scores[-1]
            if last_score > 30 and base_score > 30:
                base_score = min(100, base_score * self.risk_compound_rate)
            elif base_score < 20 and last_score > 20:
                base_score = max(0, last_score - (last_score * self.risk_decay_rate))

        final_score = max(0, min(100, base_score))
        self.user_risk_history[user_id].append(final_score)

        if len(self.user_risk_history[user_id]) > 50:
            self.user_risk_history[user_id] = self.user_risk_history[user_id][-50:]

        return round(final_score, 1)

    def get_risk_level(self, score):
        for level, (low, high) in RISK_THRESHOLDS.items():
            if low <= score < high:
                return level
        return "red" if score >= 80 else "green"

    def get_action(self, risk_level):
        return RISK_ACTIONS.get(risk_level, "Normal monitoring")

    def generate_narrative(self, username, score, risk_level, feature_scores, peer_deviations, activities):
        """Generate human-readable threat narrative using explainable AI."""
        factors = []

        if feature_scores.get("login_time_deviation", 0) > 2:
            login_hours = [a.timestamp.strftime("%I:%M %p") for a in activities if a.action_type == "login"]
            time_str = login_hours[0] if login_hours else "unusual time"
            factors.append(f"logged in at {time_str} (significantly outside typical pattern)")

        if feature_scores.get("off_hours_activity_count", 0) > 0:
            count = int(feature_scores["off_hours_activity_count"])
            factors.append(f"{count} actions performed outside normal business hours (9 AM - 6 PM)")

        if feature_scores.get("anomalous_location_count", 0) > 0:
            locs = set(a.location for a in activities if a.location and "VPN" in a.location or "Proxy" in a.location or "Tor" in a.location)
            if locs:
                factors.append(f"access from suspicious location(s): {', '.join(locs)}")
            else:
                factors.append("access from unusual location")

        if feature_scores.get("data_volume_deviation", 0) > 2:
            total_vol = sum(a.data_volume_mb for a in activities)
            factors.append(f"downloaded {total_vol:.1f} MB of data (abnormally high volume)")

        if feature_scores.get("new_resource_count", 0) > 3:
            count = int(feature_scores["new_resource_count"])
            factors.append(f"accessed {count} resources never accessed before")

        if feature_scores.get("honeypot_access_count", 0) > 0:
            honeypots = [a.resource for a in activities if a.resource in HONEYPOT_RESOURCES]
            factors.append(f"CRITICAL: accessed honeypot decoy resource(s): {', '.join(set(honeypots))}")

        if feature_scores.get("failed_login_count", 0) > 0:
            count = int(feature_scores["failed_login_count"])
            factors.append(f"{count} failed login attempt(s) before successful access")

        if feature_scores.get("anomalous_device_count", 0) > 0:
            devices = set(a.device for a in activities if "Unknown" in (a.device or "") or "Personal" in (a.device or ""))
            if devices:
                factors.append(f"access from unrecognized device(s): {', '.join(devices)}")

        for dev in peer_deviations:
            factors.append(f"Peer group deviation: {dev}")

        if not factors:
            return f"User {username} shows normal activity patterns. Risk score: {score:.0f}/100."

        factors_text = "; ".join(factors)

        threat_type = "potential insider threat"
        if feature_scores.get("honeypot_access_count", 0) > 0:
            threat_type = "likely compromised account or deliberate data breach attempt"
        elif feature_scores.get("data_volume_deviation", 0) > 3:
            threat_type = "potential data exfiltration"
        elif feature_scores.get("anomalous_location_count", 0) > 0 and feature_scores.get("new_resource_count", 0) > 3:
            threat_type = "suspected compromised account"
        elif feature_scores.get("new_resource_count", 0) > 5:
            threat_type = "potential privilege escalation or reconnaissance"

        narrative = (
            f"ALERT - User '{username}' flagged as {threat_type}. "
            f"Risk Score: {score:.0f}/100 ({risk_level.upper()}). "
            f"Key findings: {factors_text}. "
            f"Recommended action: {self.get_action(risk_level)}."
        )
        return narrative

    def generate_contributing_factors(self, feature_scores, peer_deviations):
        """Return structured list of contributing factors with weights."""
        factors = []

        factor_labels = {
            "login_time_deviation": ("Unusual login time", 0.15),
            "activity_count_deviation": ("Abnormal activity volume", 0.10),
            "session_duration_deviation": ("Unusual session length", 0.08),
            "data_volume_deviation": ("High data transfer volume", 0.15),
            "new_resource_count": ("New resource access", 0.12),
            "anomalous_location_count": ("Suspicious location", 0.15),
            "failed_login_count": ("Failed login attempts", 0.08),
            "off_hours_activity_count": ("Off-hours activity", 0.10),
            "anomalous_device_count": ("Unknown device", 0.07),
            "honeypot_access_count": ("Honeypot trap triggered", 0.25),
            "sensitive_resource_ratio": ("High sensitive resource ratio", 0.08),
        }

        for key, (label, weight) in factor_labels.items():
            value = feature_scores.get(key, 0)
            if value > 0.5:
                contribution = min(value * weight * 100, 100)
                factors.append({
                    "factor": label,
                    "value": round(value, 2),
                    "contribution": round(contribution, 1),
                    "weight": weight,
                })

        for dev in peer_deviations:
            factors.append({
                "factor": f"Peer deviation: {dev}",
                "value": 1,
                "contribution": 15.0,
                "weight": 0.15,
            })

        factors.sort(key=lambda x: x["contribution"], reverse=True)
        return factors


risk_engine = RiskEngine()
