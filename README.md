<p align="center">
  <h1 align="center">🛡️ SussedOut</h1>
  <p align="center">
    <strong>Intelligent Zero Trust Security System with AI-Powered Anomaly Detection</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
    <img src="https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="Scikit-learn" />
    <img src="https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  </p>
</p>

---

## 🔗 Live Demo Links

* 💻 **Frontend Web App (Vercel):** [https://frontend-phi-ashy-42.vercel.app](https://frontend-phi-ashy-42.vercel.app)
* ⚙️ **Backend API (Render):** [https://sussedout-backend.onrender.com](https://sussedout-backend.onrender.com)
* 📖 **Interactive API Docs:** [https://sussedout-backend.onrender.com/docs](https://sussedout-backend.onrender.com/docs)

---

## 📋 Problem Statement

**PS0106** — Intelligent Zero Trust Security System with Anomaly Detection

Modern organizations face escalating risks from **insider threats** — authorized users misusing access or compromised accounts operating under legitimate credentials. Traditional perimeter-based security systems rely on static rules and fail to adapt to evolving user behaviour. SussedOut bridges this gap with machine learning that models normal user behaviour and detects anomalies in real time.

## 🎯 What is SussedOut?

SussedOut is an **AI-powered security platform** that implements the Zero Trust principle: *"Never trust, always verify."* It continuously monitors every user's digital behaviour, builds a unique **Behavioral DNA** profile, and detects insider threats using **12 novel detection engines** working in an ensemble.

### Key Capabilities

| Capability | Description |
|---|---|
| 🧬 **Behavioral DNA** | Statistical fingerprint of each user's normal activity patterns |
| 🤖 **Isolation Forest ML** | Unsupervised anomaly detection — no labeled attack data needed |
| 📊 **Dynamic Risk Scoring** | 0–100 score with compounding (1.3×) and decay (5%) mechanics |
| 🧠 **Explainable AI** | Human-readable threat narratives for every alert |
| 🍯 **Honeypot Traps** | Fake sensitive files that trigger instant high-risk alerts |
| 🔗 **Risk Contagion Graph** | Propagates risk to behaviorally similar users |
| ⚡ **Real-Time WebSocket** | Live alerts and dashboard updates |
| 📄 **PDF Reports** | Professional threat assessment reports per user |
| 🎮 **12 Attack Simulations** | Live demo of all threat scenarios |
| 🔒 **Zero Trust Policy Engine** | Graduated response: MFA → Restrict → Block → Terminate |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React + Vite)                  │
│  Dashboard │ Users │ Alerts │ Analytics │ Simulation Panel      │
│  Real-time WebSocket Connection │ Recharts Visualizations       │
└───────────────────────────┬─────────────────────────────────────┘
                            │ REST API + WebSocket
┌───────────────────────────▼─────────────────────────────────────┐
│                     BACKEND (FastAPI + Python)                   │
│                                                                  │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │  ML Engine   │  │  Risk Engine  │  │  Policy Engine       │  │
│  │  (Isolation  │  │  (Dynamic     │  │  (Zero Trust         │  │
│  │   Forest +   │  │   Scoring +   │  │   Graduated          │  │
│  │   Behavioral │  │   Compound +  │  │   Response)          │  │
│  │   DNA)       │  │   Decay)      │  │                      │  │
│  └──────────────┘  └───────────────┘  └──────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              12 NOVEL DETECTION ENGINES                   │   │
│  │  Markov Chain │ Contagion Graph │ Evasion Detector        │   │
│  │  Credential Sharing │ Data Staging │ Ghost Account        │   │
│  │  Privilege Creep │ Kill Chain │ Biometric Shift           │   │
│  │  Coordinated Attack │ Micro-Burst │ Entropy Monitor       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────┐  ┌─────────────────────────────────────┐  │
│  │  Data Generator  │  │  SQLite + SQLAlchemy ORM            │  │
│  │  (20 Users ×     │  │  Users │ ActivityLogs │ RiskScores  │  │
│  │   30 Days +      │  │  Alerts                             │  │
│  │   12 Attacks)    │  │                                     │  │
│  └──────────────────┘  └─────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧠 The 12 Novel Detection Engines

These are research-grade techniques that make SussedOut unique:

| # | Engine | Technique | What It Detects |
|---|--------|-----------|-----------------|
| 1 | **Behavioral Markov Chain** | First-order transition probability matrix | Unusual action sequences (e.g., login→download→download instead of login→email→files) |
| 2 | **Risk Contagion Graph** | Graph-based risk propagation via behavioral similarity | Risk spreading across users who share behavioral patterns |
| 3 | **Adversarial Evasion Detector** | Stealth pattern analysis | Attackers who deliberately mimic normal behavior to avoid detection |
| 4 | **Credential Sharing Detector** | Multi-IP/device session analysis | Same account used from multiple locations/devices simultaneously |
| 5 | **Data Staging Detector** | Multi-phase exfiltration tracking (Recon → Collect → Stage → Exfil) | Slow, deliberate data hoarding before exfiltration |
| 6 | **Ghost Account Detector** | Dormancy-resurrection analysis | Inactive accounts suddenly becoming active (compromised credentials) |
| 7 | **Privilege Creep Detector** | Role-resource matrix + sprawl percentage | Users accessing resources far outside their department's scope |
| 8 | **Kill Chain Detector** | Multi-phase attack progression (7 phases) | Full attack lifecycle from reconnaissance to exfiltration |
| 9 | **Behavioral Biometric Shift** | KL-divergence on typing/activity rhythm distributions | Operator change mid-session (someone else using the account) |
| 10 | **Coordinated Attack Detector** | Temporal correlation across multiple users | APT-style attacks where multiple accounts are compromised simultaneously |
| 11 | **Micro-Burst Exfiltration** | Sub-threshold burst detection | Small, rapid data transfers designed to stay below volume alerts |
| 12 | **Entropy Monitor** | Shannon entropy of resource access patterns | Sudden access to highly diverse, unusual resources |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.10+, FastAPI, Uvicorn |
| **Machine Learning** | Scikit-learn (Isolation Forest), NumPy |
| **Database** | SQLite + SQLAlchemy ORM |
| **Frontend** | React 18, Vite 6, TailwindCSS 4 |
| **Visualization** | Recharts, Lucide React Icons |
| **Real-Time** | WebSocket (native FastAPI) |
| **Reports** | ReportLab (PDF generation) |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard` | Dashboard overview with risk distribution, alert counts |
| `GET` | `/api/users` | All users with latest risk scores |
| `GET` | `/api/users/{id}` | Detailed user profile, risk history, activities, alerts |
| `GET` | `/api/alerts` | Alerts list with severity/resolved filters |
| `GET` | `/api/activity` | Activity logs with user/anomaly filters |
| `GET` | `/api/analytics` | Charts data: department risk, hourly activity, trends |
| `GET` | `/api/contagion/{id}` | Risk contagion network for a user |
| `GET` | `/api/coordinated_attacks` | Coordinated attack detection results |
| `GET` | `/api/report/{id}` | Download PDF threat assessment report |
| `POST` | `/api/simulate/{scenario}` | Trigger live attack simulation (12 scenarios) |
| `POST` | `/api/analyze` | Re-run ML analysis on all users |
| `WS` | `/ws` | Real-time alert and risk update stream |

---

## 🎮 Attack Simulations

SussedOut includes **12 live attack scenarios** that can be triggered from the Simulation Panel:

1. **Data Exfiltration** — Bulk downloading sensitive files at unusual hours
2. **Compromised Account** — Impossible travel detection (Mumbai → London in 5 mins)
3. **Slow Insider** — Gradually escalating unauthorized access over days
4. **Credential Sharing** — Two different IPs using the same account
5. **Data Staging** — Pre-exfiltration data hoarding across 4 phases
6. **Ghost Account** — Dormant account suddenly becoming active
7. **Privilege Creep** — Accessing resources outside department scope
8. **Kill Chain** — Full 7-phase attack from recon to exfiltration
9. **Biometric Shift** — Typing/activity rhythm change (operator swap)
10. **Coordinated APT** — Multi-account simultaneous compromise
11. **Micro-Burst Exfiltration** — Hidden high-volume data bursts
12. **Entropy Spike** — Sudden access to diverse unusual resources

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

### Backend Setup

```bash
cd backend
pip install -r ../requirements.txt
python main.py
```

The backend starts at `http://localhost:8000`. On first run, it:
1. Initializes the SQLite database
2. Generates synthetic data (20 users × 30 days)
3. Trains the Isolation Forest ML model
4. Trains all 12 novel detection engines
5. Runs initial risk analysis on all users

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend starts at `http://localhost:5173` and proxies API calls to the backend.

---

## 🔐 How the Risk Engine Works

```
User Activity → Behavioral DNA Comparison → Isolation Forest Anomaly Score
                                                      │
                                          ┌───────────▼───────────┐
                                          │  12 Novel Engines     │
                                          │  (weighted ensemble)  │
                                          └───────────┬───────────┘
                                                      │
                                          ┌───────────▼───────────┐
                                          │  Dynamic Risk Score   │
                                          │  (0-100, compound     │
                                          │   + decay mechanics)  │
                                          └───────────┬───────────┘
                                                      │
                              ┌────────────┬──────────┼──────────┬────────────┐
                              ▼            ▼          ▼          ▼            ▼
                          GREEN        YELLOW      ORANGE       RED      CRITICAL
                          (0-30)       (30-60)     (60-80)    (80-100)
                          Normal       MFA +       Restrict    Terminate
                          Monitor      Enhanced    Access      Session +
                                       Logging                 Alert Team
```

---

## 👥 Team

**Team Name:** Straw Hat Coders

| Name | Role |
|------|------|
| Fain Farooq Attar | Backend & ML |
| Bushra Asif Sayyed | Frontend & UI |

---

## 📄 License

Built for hackathon evaluation purposes.
