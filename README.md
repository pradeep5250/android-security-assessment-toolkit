# 🛡️ ASAT — Android Security Assessment Toolkit

A professional-grade Android security testing platform with a premium dark-themed web dashboard, built for **educational purposes and authorized penetration testing only**.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ⚡ Features

### 🔍 Security Analysis
- **APK Analyzer** — Manifest parsing, permission classification, exported component detection, risk scoring
- **Network Scanner** — Async port scanning, DNS lookup, SSL/TLS inspection, HTTP security headers
- **Device Auditor** — Root detection, patch level assessment, security posture scoring
- **Risk Engine** — Weighted severity scoring with actionable recommendations

### 📱 ADB Automation
- Device discovery and management
- Package manager (list, install, uninstall)
- Logcat viewer with live streaming
- Screenshot and screen recording
- File push/pull
- Running services inspection

### 📊 Reporting
- **PDF** — Branded reports with ReportLab
- **HTML** — Self-contained dark-themed reports
- **CSV** — Export findings for analysis

### 🖥️ Dashboard
- Premium glassmorphism dark UI
- Real-time WebSocket updates
- Interactive charts (Chart.js)
- Responsive layout

### 🔐 Security
- JWT authentication (access + refresh tokens)
- Role-based access control (Admin / Analyst / Viewer)
- Audit logging middleware
- Rate limiting
- ADB command whitelisting (injection prevention)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- (Optional) Android SDK Platform Tools for ADB features

### Installation

```bash
# Clone the project
cd "d:\project\android hacking"

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# Install dependencies
cd backend
pip install -r requirements.txt

# Run the server
cd ..
python -m uvicorn backend.app.main:app --reload --port 8000
```

### Access
- **Dashboard**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### First Login
1. Open http://localhost:8000
2. Click "Register here"
3. Create your account — **first user automatically becomes Admin**
4. Log in with your credentials

---

## 📁 Project Structure

```
android-hacking/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI entry point
│   │   ├── config.py        # Environment settings
│   │   ├── database.py      # SQLAlchemy async engine
│   │   ├── models/          # ORM models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── api/             # API route handlers
│   │   ├── core/            # Business logic
│   │   ├── middleware/       # Audit & rate limiting
│   │   └── utils/           # Validators & helpers
│   └── requirements.txt
├── frontend/
│   ├── index.html           # SPA shell
│   ├── css/                 # Design system
│   └── js/                  # Components & pages
├── docker-compose.yml
└── .env
```

---

## 🔧 API Endpoints

| Group | Endpoints |
|-------|-----------|
| **Auth** | `POST /api/v1/auth/register`, `login`, `refresh`, `GET /me` |
| **Devices** | `GET /api/v1/devices/`, `POST /sync`, `POST /{id}/audit` |
| **ADB** | `GET /api/v1/adb/devices`, `device/{serial}/info`, `packages`, `screenshot`, `logcat` |
| **Scanner** | `POST /api/v1/scanner/port-scan`, `dns-lookup`, `ssl-check`, `http-headers`, `whois`, `ping`, `traceroute` |
| **APK** | `POST /api/v1/apk/analyze` |
| **Reports** | `POST /api/v1/reports/generate`, `GET /`, `GET /{id}/download` |

Full interactive docs at `/docs` (Swagger UI).

---

## ⚠️ Legal Disclaimer

This toolkit is designed for **educational purposes and authorized security testing only**.

- ✅ Use on devices you own or have explicit written permission to test
- ✅ Use in lab/emulator environments for learning
- ❌ Do NOT use for unauthorized access to any device or network
- ❌ Do NOT use to bypass Android permissions or exploit vulnerabilities

The developers are not responsible for any misuse of this software.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
