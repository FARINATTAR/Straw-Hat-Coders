import os

DATABASE_URL = "sqlite:///./sussedout.db"

DEPARTMENTS = ["Engineering", "Finance", "HR"]
ROLES = {
    "Engineering": ["Developer", "DevOps", "QA Engineer", "Tech Lead"],
    "Finance": ["Analyst", "Accountant", "Auditor", "Finance Manager"],
    "HR": ["Recruiter", "HR Specialist", "Payroll Admin", "HR Manager"],
}

RESOURCES = {
    "Engineering": [
        "repo:frontend-app", "repo:backend-api", "repo:infra-config",
        "repo:ml-pipeline", "wiki:engineering-docs", "ci:jenkins-pipeline",
        "db:dev-database", "cloud:aws-console", "tool:jira-board",
    ],
    "Finance": [
        "file:quarterly-report.xlsx", "file:budget-2026.xlsx",
        "file:invoice-archive.zip", "db:finance-database",
        "app:sap-system", "file:tax-filings.pdf", "app:expense-portal",
    ],
    "HR": [
        "file:employee-records.csv", "app:recruitment-portal",
        "file:performance-reviews.xlsx", "db:hr-database",
        "app:payroll-system", "file:benefits-plan.pdf",
    ],
    "Shared": [
        "app:email-client", "app:slack", "app:calendar",
        "wiki:company-handbook", "file:org-chart.pdf",
    ],
}

HONEYPOT_RESOURCES = [
    "file:salary_data_all_employees_2026.xlsx",
    "file:admin_credentials_backup.txt",
    "file:board_meeting_confidential.pdf",
    "db:executive-compensation-db",
    "file:merger_acquisition_plans.docx",
]

RISK_THRESHOLDS = {
    "green": (0, 30),
    "yellow": (30, 60),
    "orange": (60, 80),
    "red": (80, 100),
}

RISK_ACTIONS = {
    "green": "Normal monitoring",
    "yellow": "Enhanced monitoring + MFA re-verification required",
    "orange": "Sensitive resource access restricted",
    "red": "Session terminated + Security team alerted",
}

TYPICAL_WORK_HOURS = (9, 18)  # 9 AM to 6 PM

LOCATIONS = [
    "New York, US", "San Francisco, US", "London, UK",
    "Mumbai, India", "Tokyo, Japan", "Berlin, Germany",
]

ANOMALOUS_LOCATIONS = [
    "Unknown VPN, Russia", "Tor Exit Node", "Proxy, China",
    "VPN, North Korea", "Anonymous Proxy",
]
