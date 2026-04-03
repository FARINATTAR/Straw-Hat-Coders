import random
import numpy as np
from datetime import datetime, timedelta
from models import SessionLocal, User, ActivityLog, init_db
from config import (
    DEPARTMENTS, ROLES, RESOURCES, HONEYPOT_RESOURCES,
    LOCATIONS, ANOMALOUS_LOCATIONS, TYPICAL_WORK_HOURS,
)

FIRST_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry",
    "Ivy", "Jack", "Karen", "Leo", "Mona", "Nathan", "Olivia", "Paul",
    "Quinn", "Rachel", "Steve", "Tina",
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
]

DEVICES = [
    "Windows-Laptop-Corp", "MacBook-Pro-Corp", "Linux-Workstation",
    "Windows-Desktop-Corp", "MacBook-Air-Corp",
]
ANOMALOUS_DEVICES = ["Unknown-Device", "Personal-Phone", "Public-Kiosk"]

ACTION_TYPES = ["login", "file_access", "download", "api_call", "logout"]


def generate_users(db):
    users = []
    for i in range(20):
        dept = DEPARTMENTS[i % 3]
        role = random.choice(ROLES[dept])
        location = random.choice(LOCATIONS)
        typical_hour = random.randint(8, 10)
        user = User(
            username=f"{FIRST_NAMES[i].lower()}.{LAST_NAMES[i].lower()}",
            full_name=f"{FIRST_NAMES[i]} {LAST_NAMES[i]}",
            email=f"{FIRST_NAMES[i].lower()}.{LAST_NAMES[i].lower()}@company.com",
            department=dept,
            role=role,
            typical_login_hour=typical_hour,
            typical_location=location,
            is_active=True,
        )
        db.add(user)
        users.append(user)
    db.commit()
    for u in users:
        db.refresh(u)
    return users


def generate_normal_activity(db, user, base_date, num_days=30):
    """Generate normal behavioral baseline for a user over num_days."""
    logs = []
    dept_resources = RESOURCES.get(user.department, []) + RESOURCES["Shared"]

    for day_offset in range(num_days):
        current_date = base_date - timedelta(days=num_days - day_offset)

        if random.random() < 0.15:
            continue

        login_hour = max(0, min(23, int(np.random.normal(user.typical_login_hour, 0.7))))
        login_minute = random.randint(0, 59)
        login_time = current_date.replace(hour=login_hour, minute=login_minute, second=random.randint(0, 59))

        session_duration = max(15, np.random.normal(480, 60))

        logs.append(ActivityLog(
            user_id=user.id, username=user.username, timestamp=login_time,
            action_type="login", resource="auth:main-portal",
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location,
            device=random.choice(DEVICES[:3]),
            data_volume_mb=0, session_duration_min=session_duration,
            is_anomalous=False,
        ))

        num_actions = random.randint(5, 20)
        for j in range(num_actions):
            action_time = login_time + timedelta(minutes=random.randint(1, int(session_duration)))
            resource = random.choice(dept_resources)
            action_type = random.choice(["file_access", "api_call", "download"])
            volume = round(random.uniform(0.1, 5.0), 2) if action_type == "download" else 0

            logs.append(ActivityLog(
                user_id=user.id, username=user.username, timestamp=action_time,
                action_type=action_type, resource=resource,
                ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                location=user.typical_location,
                device=random.choice(DEVICES[:3]),
                data_volume_mb=volume, session_duration_min=0,
                is_anomalous=False,
            ))

        logout_time = login_time + timedelta(minutes=int(session_duration))
        logs.append(ActivityLog(
            user_id=user.id, username=user.username, timestamp=logout_time,
            action_type="logout", resource="auth:main-portal",
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location,
            device=random.choice(DEVICES[:3]),
            data_volume_mb=0, session_duration_min=0,
            is_anomalous=False,
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_anomalies_data_exfiltrator(db, user, target_date):
    """Scenario 1: data exfiltration at unusual hours with bulk downloads."""
    logs = []
    login_time = target_date - timedelta(minutes=5)
    reasons = "Off-hours login; Bulk download of sensitive files; Unusual data volume"

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=login_time,
        action_type="login", resource="auth:main-portal",
        ip_address="192.168.99.55", location=user.typical_location,
        device="Windows-Laptop-Corp", data_volume_mb=0, session_duration_min=45,
        is_anomalous=True, anomaly_reasons=reasons,
    ))

    all_resources = []
    for dept_res in RESOURCES.values():
        all_resources.extend(dept_res)

    for i in range(47):
        t = login_time + timedelta(minutes=random.randint(1, 40))
        logs.append(ActivityLog(
            user_id=user.id, username=user.username, timestamp=t,
            action_type="download", resource=random.choice(all_resources),
            ip_address="192.168.99.55", location=user.typical_location,
            device="Windows-Laptop-Corp",
            data_volume_mb=round(random.uniform(5.0, 25.0), 2),
            session_duration_min=0,
            is_anomalous=True, anomaly_reasons=reasons,
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_anomalies_compromised_account(db, user, target_date):
    """Scenario 2: login from unusual location, cross-department access, honeypot trigger."""
    logs = []
    login_time = target_date - timedelta(minutes=5)
    reasons = "Unusual location; Cross-department resource access; Honeypot triggered"

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=login_time,
        action_type="failed_login", resource="auth:main-portal",
        ip_address="45.33.12.88", location="Unknown VPN, Russia",
        device="Unknown-Device", data_volume_mb=0, session_duration_min=0,
        is_anomalous=True, anomaly_reasons="Failed login from anomalous location",
    ))

    logs.append(ActivityLog(
        user_id=user.id, username=user.username,
        timestamp=login_time + timedelta(minutes=2),
        action_type="login", resource="auth:main-portal",
        ip_address="45.33.12.88", location="Unknown VPN, Russia",
        device="Unknown-Device", data_volume_mb=0, session_duration_min=90,
        is_anomalous=True, anomaly_reasons=reasons,
    ))

    other_depts = [d for d in DEPARTMENTS if d != user.department]
    for i in range(15):
        dept = random.choice(other_depts)
        t = login_time + timedelta(minutes=random.randint(3, 60))
        logs.append(ActivityLog(
            user_id=user.id, username=user.username, timestamp=t,
            action_type="file_access", resource=random.choice(RESOURCES[dept]),
            ip_address="45.33.12.88", location="Unknown VPN, Russia",
            device="Unknown-Device", data_volume_mb=round(random.uniform(0.5, 8.0), 2),
            session_duration_min=0,
            is_anomalous=True, anomaly_reasons=reasons,
        ))

    honeypot_time = login_time + timedelta(minutes=35)
    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=honeypot_time,
        action_type="file_access", resource=random.choice(HONEYPOT_RESOURCES),
        ip_address="45.33.12.88", location="Unknown VPN, Russia",
        device="Unknown-Device", data_volume_mb=0,
        session_duration_min=0,
        is_anomalous=True, anomaly_reasons="HONEYPOT TRIGGERED - " + reasons,
    ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_anomalies_slow_insider(db, user, base_date):
    """Scenario 3: gradually escalating access over 7 days."""
    logs = []
    other_depts = [d for d in DEPARTMENTS if d != user.department]

    for day in range(7):
        current_date = base_date - timedelta(days=7 - day)
        login_hour = user.typical_login_hour
        login_time = current_date.replace(hour=login_hour, minute=random.randint(0, 59))

        extra_accesses = 2 + day * 3
        reasons = f"Gradually escalating access pattern (day {day+1}/7); Cross-department resource access increasing"

        dept_resources = RESOURCES.get(user.department, []) + RESOURCES["Shared"]
        for i in range(random.randint(5, 10)):
            t = login_time + timedelta(minutes=random.randint(1, 400))
            logs.append(ActivityLog(
                user_id=user.id, username=user.username, timestamp=t,
                action_type=random.choice(["file_access", "api_call"]),
                resource=random.choice(dept_resources),
                ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                location=user.typical_location,
                device=random.choice(DEVICES[:3]),
                data_volume_mb=0, session_duration_min=0,
                is_anomalous=False,
            ))

        for i in range(extra_accesses):
            dept = random.choice(other_depts)
            t = login_time + timedelta(minutes=random.randint(1, 400))
            volume = round(random.uniform(0.5, 3.0 + day * 1.5), 2)
            logs.append(ActivityLog(
                user_id=user.id, username=user.username, timestamp=t,
                action_type=random.choice(["file_access", "download"]),
                resource=random.choice(RESOURCES[dept]),
                ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                location=user.typical_location,
                device=random.choice(DEVICES[:3]),
                data_volume_mb=volume, session_duration_min=0,
                is_anomalous=True, anomaly_reasons=reasons,
            ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_credential_sharing(db, user, target_date):
    """Scenario 4: Two humans using same account — impossible travel + concurrent sessions."""
    logs = []
    reasons = "Credential sharing: impossible travel + concurrent sessions from different IPs/devices"

    t1 = target_date - timedelta(minutes=30)
    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t1,
        action_type="login", resource="auth:main-portal",
        ip_address="10.0.5.42", location="Mumbai, India",
        device="Windows-Laptop-Corp", data_volume_mb=0, session_duration_min=60,
        is_anomalous=True, anomaly_reasons=reasons,
    ))
    for i in range(5):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t1 + timedelta(minutes=random.randint(1, 15)),
            action_type="file_access",
            resource=random.choice(RESOURCES.get(user.department, []) + RESOURCES["Shared"]),
            ip_address="10.0.5.42", location="Mumbai, India",
            device="Windows-Laptop-Corp", data_volume_mb=round(random.uniform(0.1, 2.0), 2),
            session_duration_min=0, is_anomalous=True, anomaly_reasons=reasons,
        ))

    t2 = t1 + timedelta(minutes=5)
    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t2,
        action_type="login", resource="auth:main-portal",
        ip_address="45.89.23.101", location="London, UK",
        device="Unknown-Device", data_volume_mb=0, session_duration_min=30,
        is_anomalous=True, anomaly_reasons="IMPOSSIBLE TRAVEL: Mumbai -> London in 5 min",
    ))
    for i in range(12):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t2 + timedelta(minutes=random.randint(1, 25)),
            action_type="download",
            resource=random.choice([r for dept_res in RESOURCES.values() for r in dept_res]),
            ip_address="45.89.23.101", location="London, UK",
            device="Unknown-Device", data_volume_mb=round(random.uniform(5.0, 20.0), 2),
            session_duration_min=0, is_anomalous=True, anomaly_reasons=reasons,
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_data_staging(db, user, target_date):
    """Scenario 5: Pre-exfiltration staging — collecting files from multiple departments."""
    logs = []
    reasons = "Data staging: cross-department resource collection before exfiltration (MITRE T1074)"

    all_resources = []
    for dept, res in RESOURCES.items():
        if dept != "Shared":
            all_resources.extend(res)

    t = target_date - timedelta(minutes=60)
    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        location=user.typical_location, device="Windows-Laptop-Corp",
        data_volume_mb=0, session_duration_min=90,
        is_anomalous=True, anomaly_reasons=reasons,
    ))

    used = set()
    for i in range(25):
        resource = random.choice(all_resources)
        used.add(resource)
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(1, 55)),
            action_type=random.choice(["file_access", "download"]),
            resource=resource,
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location, device="Windows-Laptop-Corp",
            data_volume_mb=round(random.uniform(0.5, 8.0), 2),
            session_duration_min=0, is_anomalous=True, anomaly_reasons=reasons,
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_ghost_account(db, user, target_date):
    """Scenario 6: Dormant account suddenly reactivated with sensitive access."""
    db.query(ActivityLog).filter(
        ActivityLog.user_id == user.id,
        ActivityLog.timestamp >= target_date - timedelta(days=25),
    ).delete()
    db.commit()

    logs = []
    reasons = "Ghost account resurrection: dormant 20+ days, now performing sensitive operations"

    t = target_date - timedelta(minutes=10)
    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address="91.220.13.44", location="Anonymous Proxy",
        device="Unknown-Device", data_volume_mb=0, session_duration_min=30,
        is_anomalous=True, anomaly_reasons=reasons,
    ))

    all_sensitive = []
    for dept_res in RESOURCES.values():
        all_sensitive.extend(dept_res)
    all_sensitive.extend(HONEYPOT_RESOURCES[:2])

    for i in range(10):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(1, 25)),
            action_type=random.choice(["file_access", "download"]),
            resource=random.choice(all_sensitive),
            ip_address="91.220.13.44", location="Anonymous Proxy",
            device="Unknown-Device",
            data_volume_mb=round(random.uniform(2.0, 15.0), 2),
            session_duration_min=0, is_anomalous=True, anomaly_reasons=reasons,
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_privilege_creep(db, user, target_date):
    """Scenario 7: User accessing resources far outside their department role."""
    logs = []
    reasons = "Privilege creep: accessing resources from multiple departments outside assigned role"

    other_depts = [d for d in DEPARTMENTS if d != user.department]
    t = target_date - timedelta(minutes=30)

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        location=user.typical_location, device="Windows-Laptop-Corp",
        data_volume_mb=0, session_duration_min=60,
        is_anomalous=True, anomaly_reasons=reasons,
    ))

    for dept in other_depts:
        dept_resources = RESOURCES[dept]
        for i in range(8):
            logs.append(ActivityLog(
                user_id=user.id, username=user.username,
                timestamp=t + timedelta(minutes=random.randint(1, 55)),
                action_type=random.choice(["file_access", "download", "api_call"]),
                resource=random.choice(dept_resources),
                ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                location=user.typical_location, device="Windows-Laptop-Corp",
                data_volume_mb=round(random.uniform(0.5, 5.0), 2),
                session_duration_min=0, is_anomalous=True, anomaly_reasons=reasons,
            ))

    own_resources = RESOURCES.get(user.department, []) + RESOURCES["Shared"]
    for i in range(3):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(1, 55)),
            action_type="file_access",
            resource=random.choice(own_resources),
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location, device="Windows-Laptop-Corp",
            data_volume_mb=0, session_duration_min=0,
            is_anomalous=False,
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_kill_chain(db, user, target_date):
    """Scenario 8: User progresses through full kill chain — recon to exfiltration."""
    logs = []
    all_resources = [r for dept_res in RESOURCES.values() for r in dept_res]
    other_depts = [d for d in DEPARTMENTS if d != user.department]
    t = target_date - timedelta(minutes=90)

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address="10.0.5.100", location=user.typical_location,
        device="Windows-Laptop-Corp", data_volume_mb=0, session_duration_min=120,
        is_anomalous=True, anomaly_reasons="Kill chain: full attack progression detected",
    ))
    for i in range(8):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(1, 15)),
            action_type="file_access", resource=random.choice(all_resources),
            ip_address="10.0.5.100", location=user.typical_location,
            device="Windows-Laptop-Corp", data_volume_mb=0, session_duration_min=0,
            is_anomalous=True, anomaly_reasons="Kill chain phase: Reconnaissance",
        ))
    for dept in other_depts:
        for i in range(5):
            logs.append(ActivityLog(
                user_id=user.id, username=user.username,
                timestamp=t + timedelta(minutes=random.randint(20, 40)),
                action_type=random.choice(["file_access", "api_call"]),
                resource=random.choice(RESOURCES[dept]),
                ip_address="10.0.5.100", location=user.typical_location,
                device="Windows-Laptop-Corp", data_volume_mb=round(random.uniform(0.1, 3.0), 2),
                session_duration_min=0, is_anomalous=True,
                anomaly_reasons="Kill chain phase: Lateral Movement + Collection",
            ))
    for i in range(20):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(50, 85)),
            action_type="download", resource=random.choice(all_resources),
            ip_address="10.0.5.100", location=user.typical_location,
            device="Windows-Laptop-Corp", data_volume_mb=round(random.uniform(5.0, 25.0), 2),
            session_duration_min=0, is_anomalous=True,
            anomaly_reasons="Kill chain phase: Exfiltration",
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_biometric_shift(db, user, target_date):
    """Scenario 9: Operator change mid-session — timing rhythm shifts abruptly."""
    logs = []
    t = target_date - timedelta(minutes=40)

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        location=user.typical_location, device="Windows-Laptop-Corp",
        data_volume_mb=0, session_duration_min=60,
        is_anomalous=True, anomaly_reasons="Biometric shift: operator change detected",
    ))
    for i in range(10):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(seconds=i * random.randint(120, 300)),
            action_type=random.choice(["file_access", "api_call"]),
            resource=random.choice(RESOURCES.get(user.department, []) + RESOURCES["Shared"]),
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location, device="Windows-Laptop-Corp",
            data_volume_mb=round(random.uniform(0, 1.0), 2),
            session_duration_min=0, is_anomalous=False,
        ))
    shift_time = t + timedelta(minutes=20)
    all_resources = [r for dept_res in RESOURCES.values() for r in dept_res]
    for i in range(15):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=shift_time + timedelta(seconds=i * random.randint(5, 15)),
            action_type="download", resource=random.choice(all_resources),
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location, device="Windows-Laptop-Corp",
            data_volume_mb=round(random.uniform(3.0, 15.0), 2),
            session_duration_min=0, is_anomalous=True,
            anomaly_reasons="Biometric shift: rapid-fire actions (different operator rhythm)",
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_coordinated_attack(db, target_date):
    """Scenario 10: 3 users simultaneously compromised — coordinated APT attack."""
    from models import SessionLocal as SL
    users_to_compromise = ["karen.hernandez", "leo.lopez", "mona.gonzalez"]
    total = 0
    for username in users_to_compromise:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            continue
        logs = []
        t = target_date - timedelta(minutes=random.randint(5, 15))
        logs.append(ActivityLog(
            user_id=user.id, username=user.username, timestamp=t,
            action_type="login", resource="auth:main-portal",
            ip_address=f"45.33.{random.randint(10,99)}.{random.randint(1,254)}",
            location=random.choice(ANOMALOUS_LOCATIONS),
            device="Unknown-Device", data_volume_mb=0, session_duration_min=30,
            is_anomalous=True, anomaly_reasons="Coordinated attack: simultaneous compromise",
        ))
        all_resources = [r for dept_res in RESOURCES.values() for r in dept_res]
        for i in range(10):
            logs.append(ActivityLog(
                user_id=user.id, username=user.username,
                timestamp=t + timedelta(minutes=random.randint(1, 25)),
                action_type=random.choice(["file_access", "download"]),
                resource=random.choice(all_resources),
                ip_address=f"45.33.{random.randint(10,99)}.{random.randint(1,254)}",
                location=random.choice(ANOMALOUS_LOCATIONS),
                device="Unknown-Device",
                data_volume_mb=round(random.uniform(2.0, 15.0), 2),
                session_duration_min=0, is_anomalous=True,
                anomaly_reasons="Coordinated attack: cross-department access from anomalous location",
            ))
        db.bulk_save_objects(logs)
        total += len(logs)
    db.commit()
    return total


def inject_micro_burst(db, user, target_date):
    """Scenario 11: Hidden data bursts within normal session."""
    logs = []
    t = target_date - timedelta(minutes=60)

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        location=user.typical_location, device="Windows-Laptop-Corp",
        data_volume_mb=0, session_duration_min=90,
        is_anomalous=True, anomaly_reasons="Micro-burst exfiltration detected",
    ))
    dept_resources = RESOURCES.get(user.department, []) + RESOURCES["Shared"]
    for i in range(5):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(1, 10)),
            action_type="file_access", resource=random.choice(dept_resources),
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location, device="Windows-Laptop-Corp",
            data_volume_mb=round(random.uniform(0.1, 1.0), 2),
            session_duration_min=0, is_anomalous=False,
        ))

    all_res = [r for dept_res in RESOURCES.values() for r in dept_res]
    burst_times = [15, 35, 52]
    for burst_min in burst_times:
        burst_t = t + timedelta(minutes=burst_min)
        for j in range(6):
            logs.append(ActivityLog(
                user_id=user.id, username=user.username,
                timestamp=burst_t + timedelta(seconds=j * 8),
                action_type="download", resource=random.choice(all_res),
                ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                location=user.typical_location, device="Windows-Laptop-Corp",
                data_volume_mb=round(random.uniform(5.0, 15.0), 2),
                session_duration_min=0, is_anomalous=True,
                anomaly_reasons=f"Micro-burst #{burst_times.index(burst_min)+1}: high volume in <60s",
            ))
        for j in range(3):
            logs.append(ActivityLog(
                user_id=user.id, username=user.username,
                timestamp=burst_t + timedelta(minutes=random.randint(3, 12)),
                action_type="file_access", resource=random.choice(dept_resources),
                ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
                location=user.typical_location, device="Windows-Laptop-Corp",
                data_volume_mb=round(random.uniform(0, 0.5), 2),
                session_duration_min=0, is_anomalous=False,
            ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def inject_entropy_spike(db, user, target_date):
    """Scenario 12: User suddenly accessing highly diverse unfamiliar resources."""
    logs = []
    t = target_date - timedelta(minutes=30)

    logs.append(ActivityLog(
        user_id=user.id, username=user.username, timestamp=t,
        action_type="login", resource="auth:main-portal",
        ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        location=user.typical_location, device="Windows-Laptop-Corp",
        data_volume_mb=0, session_duration_min=45,
        is_anomalous=True, anomaly_reasons="Entropy spike: anomalous exploration pattern",
    ))

    exotic_resources = [
        "file:ceo-personal-notes.docx", "db:legacy-customer-db",
        "repo:deprecated-auth-service", "file:board-strategy-2027.pdf",
        "cloud:gcp-billing-console", "db:production-backup-full",
        "file:pen-test-results-2025.pdf", "app:admin-dashboard-hidden",
        "file:encryption-keys-backup.pem", "db:analytics-warehouse",
        "repo:internal-security-tools", "file:ip-portfolio.xlsx",
        "cloud:azure-key-vault", "app:vpn-admin-panel",
        "file:disaster-recovery-plan.pdf", "db:gdpr-deletion-queue",
        "repo:payment-gateway-v2", "file:vendor-contracts-all.zip",
        "app:siem-log-portal", "file:source-code-audit.pdf",
        "db:user-pii-archive", "cloud:aws-secrets-manager",
        "file:competitive-analysis.xlsx", "repo:devops-credentials",
        "app:root-cert-manager", "file:regulatory-filings-2026.pdf",
    ]

    for i, resource in enumerate(exotic_resources):
        logs.append(ActivityLog(
            user_id=user.id, username=user.username,
            timestamp=t + timedelta(minutes=random.randint(1, 28)),
            action_type=random.choice(["file_access", "download", "api_call"]),
            resource=resource,
            ip_address=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            location=user.typical_location, device="Windows-Laptop-Corp",
            data_volume_mb=round(random.uniform(0.5, 5.0), 2),
            session_duration_min=0, is_anomalous=True,
            anomaly_reasons="Entropy spike: accessing diverse unfamiliar resources",
        ))

    db.bulk_save_objects(logs)
    db.commit()
    return len(logs)


def generate_all_data():
    init_db()
    db = SessionLocal()

    existing = db.query(User).count()
    if existing > 0:
        print(f"Database already has {existing} users. Skipping generation.")
        db.close()
        return

    print("Generating users...")
    users = generate_users(db)
    print(f"Created {len(users)} users")

    now = datetime.utcnow()
    total_logs = 0

    print("Generating normal activity logs...")
    for user in users:
        count = generate_normal_activity(db, user, now, num_days=30)
        total_logs += count
    print(f"Generated {total_logs} normal activity logs")

    print("Injecting anomaly scenario 1: Data Exfiltrator (user: bob.johnson)...")
    exfiltrator = db.query(User).filter(User.username == "bob.johnson").first()
    if exfiltrator:
        c = inject_anomalies_data_exfiltrator(db, exfiltrator, now)
        print(f"  Injected {c} anomalous logs")

    print("Injecting anomaly scenario 2: Compromised Account (user: eve.jones)...")
    compromised = db.query(User).filter(User.username == "eve.jones").first()
    if compromised:
        c = inject_anomalies_compromised_account(db, compromised, now)
        print(f"  Injected {c} anomalous logs")

    print("Injecting anomaly scenario 3: Slow Insider (user: henry.davis)...")
    insider = db.query(User).filter(User.username == "henry.davis").first()
    if insider:
        c = inject_anomalies_slow_insider(db, insider, now)
        print(f"  Injected {c} anomalous logs")

    final_count = db.query(ActivityLog).count()
    print(f"\nTotal activity logs in database: {final_count}")
    db.close()


if __name__ == "__main__":
    generate_all_data()
