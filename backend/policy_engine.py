from datetime import datetime
from models import Alert
from config import RISK_THRESHOLDS, RISK_ACTIONS, HONEYPOT_RESOURCES


class ZeroTrustPolicyEngine:
    """
    Zero Trust Policy Engine implementing:
    - Never trust, always verify (continuous)
    - Least privilege enforcement
    - Risk-adaptive access control
    - Graduated response based on threat level
    """

    def __init__(self):
        self.session_states = {}
        self.blocked_users = set()

    def evaluate_session(self, user_id, username, risk_score, risk_level, feature_scores):
        """Evaluate current session against Zero Trust policies and return actions."""
        actions = []
        alerts = []

        if risk_level == "green":
            actions.append({
                "type": "log",
                "description": "Normal monitoring - activity logged",
                "severity": "info",
            })
            self.session_states[user_id] = "active"

        elif risk_level == "yellow":
            actions.append({
                "type": "mfa_challenge",
                "description": "Enhanced monitoring activated - MFA re-verification required",
                "severity": "warning",
            })
            actions.append({
                "type": "enhanced_logging",
                "description": "Detailed session recording enabled",
                "severity": "warning",
            })
            self.session_states[user_id] = "mfa_required"
            alerts.append(self._create_alert(
                user_id, username, "risk_threshold",
                "medium", f"User {username} risk elevated to YELLOW ({risk_score:.0f}). MFA re-verification triggered."
            ))

        elif risk_level == "orange":
            actions.append({
                "type": "restrict_access",
                "description": "Sensitive resource access RESTRICTED - read-only mode enforced",
                "severity": "high",
            })
            actions.append({
                "type": "mfa_challenge",
                "description": "Mandatory MFA re-verification",
                "severity": "high",
            })
            actions.append({
                "type": "notify_security",
                "description": "Security team notified for manual review",
                "severity": "high",
            })
            self.session_states[user_id] = "restricted"
            alerts.append(self._create_alert(
                user_id, username, "risk_threshold",
                "high", f"User {username} risk at ORANGE ({risk_score:.0f}). Sensitive access restricted. Security team notified."
            ))

        elif risk_level == "red":
            actions.append({
                "type": "terminate_session",
                "description": "Session TERMINATED - all active connections closed",
                "severity": "critical",
            })
            actions.append({
                "type": "lock_account",
                "description": "Account temporarily LOCKED pending investigation",
                "severity": "critical",
            })
            actions.append({
                "type": "notify_security",
                "description": "URGENT: Security incident response team alerted",
                "severity": "critical",
            })
            actions.append({
                "type": "preserve_evidence",
                "description": "Full session logs preserved for forensic analysis",
                "severity": "critical",
            })
            self.session_states[user_id] = "terminated"
            self.blocked_users.add(user_id)
            alerts.append(self._create_alert(
                user_id, username, "risk_threshold",
                "critical", f"CRITICAL: User {username} risk at RED ({risk_score:.0f}). Session terminated. Account locked."
            ))

        if feature_scores.get("honeypot_access_count", 0) > 0:
            actions.append({
                "type": "honeypot_triggered",
                "description": "HONEYPOT TRAP ACTIVATED - immediate investigation required",
                "severity": "critical",
            })
            alerts.append(self._create_alert(
                user_id, username, "honeypot",
                "critical", f"HONEYPOT TRIGGERED by {username}! Decoy resource accessed. Possible data breach attempt."
            ))
            self.session_states[user_id] = "terminated"
            self.blocked_users.add(user_id)

        return actions, alerts

    def _create_alert(self, user_id, username, alert_type, severity, message):
        return Alert(
            user_id=user_id,
            username=username,
            alert_type=alert_type,
            severity=severity,
            message=message,
            timestamp=datetime.utcnow(),
            is_resolved=False,
            action_taken=RISK_ACTIONS.get(severity, "Logged"),
        )

    def check_access(self, user_id, resource):
        """Zero Trust access check - verify every request."""
        if user_id in self.blocked_users:
            return False, "Account is locked due to security incident"

        state = self.session_states.get(user_id, "active")
        if state == "terminated":
            return False, "Session has been terminated"
        if state == "restricted" and resource in HONEYPOT_RESOURCES:
            return False, "Access denied - resource restricted under current security policy"

        return True, "Access granted"

    def get_session_state(self, user_id):
        return self.session_states.get(user_id, "active")

    def reset_user(self, user_id):
        self.session_states.pop(user_id, None)
        self.blocked_users.discard(user_id)


policy_engine = ZeroTrustPolicyEngine()
