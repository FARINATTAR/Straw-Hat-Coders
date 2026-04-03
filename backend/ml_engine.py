import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
from collections import defaultdict
from models import SessionLocal, User, ActivityLog
from config import HONEYPOT_RESOURCES, TYPICAL_WORK_HOURS, RESOURCES, DEPARTMENTS


class BehavioralDNA:
    """Builds a behavioral fingerprint for each user based on historical activity."""

    def __init__(self):
        self.user_profiles = {}
        self.department_profiles = {}
        self.isolation_forest = IsolationForest(
            n_estimators=100, contamination=0.1, random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def build_user_profile(self, user_id, activities):
        """Build a statistical profile of normal behavior for a user."""
        if not activities:
            return None

        login_hours = []
        session_durations = []
        data_volumes = []
        resource_counts = defaultdict(int)
        daily_actions = defaultdict(int)
        locations = defaultdict(int)
        devices = defaultdict(int)
        resources_accessed = set()

        for act in activities:
            if act.action_type == "login":
                login_hours.append(act.timestamp.hour)
                session_durations.append(act.session_duration_min)
            if act.data_volume_mb > 0:
                data_volumes.append(act.data_volume_mb)

            day_key = act.timestamp.strftime("%Y-%m-%d")
            daily_actions[day_key] += 1
            resource_counts[act.resource] += 1
            locations[act.location] += 1
            devices[act.device] += 1
            resources_accessed.add(act.resource)

        daily_counts = list(daily_actions.values()) if daily_actions else [0]

        profile = {
            "user_id": user_id,
            "mean_login_hour": np.mean(login_hours) if login_hours else 9.0,
            "std_login_hour": max(np.std(login_hours), 0.5) if login_hours else 1.0,
            "mean_session_duration": np.mean(session_durations) if session_durations else 480,
            "std_session_duration": max(np.std(session_durations), 10) if session_durations else 60,
            "mean_daily_actions": np.mean(daily_counts),
            "std_daily_actions": max(np.std(daily_counts), 1),
            "mean_data_volume": np.mean(data_volumes) if data_volumes else 0,
            "std_data_volume": max(np.std(data_volumes), 0.5) if data_volumes else 1,
            "known_resources": resources_accessed,
            "typical_locations": set(locations.keys()),
            "typical_devices": set(devices.keys()),
            "total_activities": len(activities),
        }
        self.user_profiles[user_id] = profile
        return profile

    def build_department_profile(self, department, all_user_activities):
        """Build aggregate profile for a department (peer group)."""
        dept_data_volumes = []
        dept_daily_actions = []
        dept_resources = set()
        dept_login_hours = []

        for user_id, activities in all_user_activities.items():
            daily = defaultdict(int)
            for act in activities:
                if act.action_type == "login":
                    dept_login_hours.append(act.timestamp.hour)
                if act.data_volume_mb > 0:
                    dept_data_volumes.append(act.data_volume_mb)
                day_key = act.timestamp.strftime("%Y-%m-%d")
                daily[day_key] += 1
                dept_resources.add(act.resource)
            dept_daily_actions.extend(daily.values())

        self.department_profiles[department] = {
            "mean_login_hour": np.mean(dept_login_hours) if dept_login_hours else 9,
            "std_login_hour": max(np.std(dept_login_hours), 0.5) if dept_login_hours else 1,
            "mean_data_volume": np.mean(dept_data_volumes) if dept_data_volumes else 0,
            "std_data_volume": max(np.std(dept_data_volumes), 0.5) if dept_data_volumes else 1,
            "known_resources": dept_resources,
            "mean_daily_actions": np.mean(dept_daily_actions) if dept_daily_actions else 10,
            "std_daily_actions": max(np.std(dept_daily_actions), 1) if dept_daily_actions else 5,
        }

    def extract_features(self, user_id, activities_window):
        """Extract feature vector from a window of recent activities."""
        profile = self.user_profiles.get(user_id)
        if not profile:
            return None

        login_hours = []
        total_volume = 0
        resource_set = set()
        new_resources = 0
        off_hours_count = 0
        failed_logins = 0
        anomalous_locations = 0
        anomalous_devices = 0
        honeypot_access = 0
        session_durations = []

        for act in activities_window:
            if act.action_type == "login":
                login_hours.append(act.timestamp.hour)
                session_durations.append(act.session_duration_min)
            if act.action_type == "failed_login":
                failed_logins += 1

            total_volume += act.data_volume_mb
            resource_set.add(act.resource)

            if act.resource not in profile["known_resources"]:
                new_resources += 1
            if act.resource in HONEYPOT_RESOURCES:
                honeypot_access += 1

            hour = act.timestamp.hour
            if hour < TYPICAL_WORK_HOURS[0] or hour > TYPICAL_WORK_HOURS[1]:
                off_hours_count += 1

            if act.location not in profile["typical_locations"]:
                anomalous_locations += 1
            if act.device not in profile["typical_devices"]:
                anomalous_devices += 1

        avg_login_hour = np.mean(login_hours) if login_hours else profile["mean_login_hour"]
        login_hour_deviation = abs(avg_login_hour - profile["mean_login_hour"]) / profile["std_login_hour"]

        avg_session = np.mean(session_durations) if session_durations else profile["mean_session_duration"]
        session_deviation = abs(avg_session - profile["mean_session_duration"]) / profile["std_session_duration"]

        volume_deviation = (
            abs(total_volume - profile["mean_data_volume"]) / profile["std_data_volume"]
            if profile["mean_data_volume"] > 0 else total_volume
        )

        activity_deviation = (
            abs(len(activities_window) - profile["mean_daily_actions"]) / profile["std_daily_actions"]
        )

        dept_resources = set()
        for dept_res in RESOURCES.values():
            dept_resources.update(dept_res)
        sensitive_ratio = sum(
            1 for r in resource_set if r not in RESOURCES.get("Shared", [])
        ) / max(len(resource_set), 1)

        features = np.array([
            login_hour_deviation,
            activity_deviation,
            session_deviation,
            len(resource_set),
            sensitive_ratio,
            volume_deviation,
            new_resources,
            anomalous_locations,
            failed_logins,
            off_hours_count,
            anomalous_devices,
            honeypot_access,
        ])

        return features

    def train(self, db):
        """Train the anomaly detection model on historical normal data."""
        users = db.query(User).all()
        all_features = []
        cutoff = datetime.utcnow() - timedelta(days=35)

        for user in users:
            activities = (
                db.query(ActivityLog)
                .filter(
                    ActivityLog.user_id == user.id,
                    ActivityLog.is_anomalous == False,
                    ActivityLog.timestamp >= cutoff,
                )
                .order_by(ActivityLog.timestamp)
                .all()
            )

            self.build_user_profile(user.id, activities)

        dept_activities = defaultdict(lambda: defaultdict(list))
        for user in users:
            activities = (
                db.query(ActivityLog)
                .filter(
                    ActivityLog.user_id == user.id,
                    ActivityLog.is_anomalous == False,
                    ActivityLog.timestamp >= cutoff,
                )
                .all()
            )
            dept_activities[user.department][user.id] = activities

        for dept, user_acts in dept_activities.items():
            self.build_department_profile(dept, user_acts)

        for user in users:
            activities = (
                db.query(ActivityLog)
                .filter(
                    ActivityLog.user_id == user.id,
                    ActivityLog.is_anomalous == False,
                    ActivityLog.timestamp >= cutoff,
                )
                .all()
            )
            if len(activities) < 5:
                continue

            chunk_size = max(5, len(activities) // 10)
            for i in range(0, len(activities) - chunk_size, chunk_size // 2):
                chunk = activities[i:i + chunk_size]
                feats = self.extract_features(user.id, chunk)
                if feats is not None:
                    all_features.append(feats)

        if len(all_features) < 10:
            print("Not enough data to train. Using defaults.")
            self.is_trained = False
            return

        X = np.array(all_features)
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        self.isolation_forest.fit(X_scaled)
        self.is_trained = True
        print(f"ML model trained on {len(X)} feature vectors from {len(users)} users")

    def predict_anomaly(self, user_id, activities_window):
        """Returns (is_anomaly, anomaly_score, feature_scores)."""
        features = self.extract_features(user_id, activities_window)
        if features is None:
            return False, 0.0, {}

        feature_names = [
            "login_time_deviation", "activity_count_deviation",
            "session_duration_deviation", "resource_count",
            "sensitive_resource_ratio", "data_volume_deviation",
            "new_resource_count", "anomalous_location_count",
            "failed_login_count", "off_hours_activity_count",
            "anomalous_device_count", "honeypot_access_count",
        ]

        z_scores = {}
        for i, name in enumerate(feature_names):
            z_scores[name] = float(features[i])

        if self.is_trained:
            X = self.scaler.transform(features.reshape(1, -1))
            iso_score = -self.isolation_forest.score_samples(X)[0]
            iso_pred = self.isolation_forest.predict(X)[0]
        else:
            iso_score = 0.5
            iso_pred = 1

        z_weights = {
            "login_time_deviation": 0.12,
            "activity_count_deviation": 0.08,
            "session_duration_deviation": 0.06,
            "resource_count": 0.05,
            "sensitive_resource_ratio": 0.08,
            "data_volume_deviation": 0.12,
            "new_resource_count": 0.10,
            "anomalous_location_count": 0.12,
            "failed_login_count": 0.07,
            "off_hours_activity_count": 0.10,
            "anomalous_device_count": 0.05,
            "honeypot_access_count": 0.20,
        }

        weighted_z_score = sum(
            z_scores.get(k, 0) * v for k, v in z_weights.items()
        )
        z_anomaly_score = min(weighted_z_score / 5.0, 1.0)

        if self.is_trained:
            ensemble_score = 0.6 * iso_score + 0.4 * z_anomaly_score
        else:
            ensemble_score = z_anomaly_score

        is_anomaly = ensemble_score > 0.45 or iso_pred == -1 or z_scores.get("honeypot_access_count", 0) > 0

        return is_anomaly, min(ensemble_score, 1.0), z_scores

    def get_peer_deviation(self, user_id, department, activities_window):
        """Check if user's behavior deviates from their peer group."""
        dept_profile = self.department_profiles.get(department)
        if not dept_profile:
            return 0.0, []

        deviations = []
        resources_accessed = set()
        total_volume = 0

        for act in activities_window:
            resources_accessed.add(act.resource)
            total_volume += act.data_volume_mb

        unknown_to_dept = resources_accessed - dept_profile["known_resources"]
        if unknown_to_dept:
            deviations.append(
                f"Accessed {len(unknown_to_dept)} resources never used by {department} department"
            )

        if dept_profile["mean_data_volume"] > 0:
            vol_z = (total_volume - dept_profile["mean_data_volume"]) / dept_profile["std_data_volume"]
            if vol_z > 2:
                deviations.append(
                    f"Data volume ({total_volume:.1f} MB) is {vol_z:.1f}x std dev above department average"
                )

        peer_score = min(len(deviations) * 0.3, 1.0)
        return peer_score, deviations


ml_engine = BehavioralDNA()
