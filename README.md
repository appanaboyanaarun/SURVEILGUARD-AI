# SurveilGuard AI — Real-Time Suspicious Activity Detection & Admin Monitoring System

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![OpenCV](https://img.shields.io/badge/OpenCV-4.8+-5C3EE8?style=for-the-badge&logo=opencv&logoColor=white)](https://opencv.org/)
[![Security](https://img.shields.io/badge/Security-PBKDF2%20%2B%20JWT-success?style=for-the-badge&logo=auth0&logoColor=white)](https://jwt.io/)

A complete, production-ready, browser-based surveillance monitoring platform that captures live device camera feeds, runs genuine OpenCV computer-vision person detection and unsupervised Machine Learning anomaly detection (Isolation Forest / One-Class SVM), records short evidence video clips on confirmed events, and automatically sends SMS alerts with direct browser evidence links to Admin mobile phones.

---

## 🏗️ System Architecture

```
[ ADMIN BROWSER / MOBILE PHONE ]
        │  (HTTPS / WebSocket)
        ▼
[ RESPONSIVE PWA FRONTEND ]
  ├── Device Camera (getUserMedia)
  ├── Real-time Canvas HUD (GREEN: Normal / RED: Suspicious)
  ├── Automatic MediaRecorder Evidence Capture
  └── Deep-Link Evidence Video Player
        │  (REST API / WebSocket)
        ▼
[ FASTAPI APPLICATION BACKEND ]
  ├── 🔐 Authentication & RBAC (PBKDF2-HMAC-SHA256 + JWT)
  ├── 📹 Live Detection Service (OpenCV HOG + MOG2 + Zones + ML)
  ├── ⏱️ False-Positive Confirmation & Cooldown Tracker
  ├── 👤 Detection Sessions & Admin Association
  ├── 💾 Storage Abstraction (Local / Cloud S3 with Signed Tokens)
  ├── 📱 SMS Gateway (Mock / Twilio / Vonage / HTTP Webhook)
  ├── 📋 Human Review Workflow & Annotation
  ├── 📊 Reports & CSV Compliance Export
  └── 📜 Security Audit Logging
        │
  ├── [ SQLite / PostgreSQL Database ]
  └── [ Private Storage Directory / S3 Bucket ]
```

---

## ✨ Core Features & Capabilities

1. **Genuine Browser-Based Live AI Detection**:
   - Accesses device camera (front/back on mobile phones, laptop webcams, or CCTV feeds).
   - Real OpenCV person detection (`PersonDetector`), background subtraction (`MOG2`), and polygon restricted zone collision analysis (`RestrictedZone`).
   - Unsupervised Machine Learning anomaly scoring (`IsolationForest` / `OneClassSVM`) in `< 15ms`.
   - Real-time HUD clearly displays:
     - 🟢 **"No suspicious activity detected"** (Normal routine)
     - 🔴 **"Suspicious activity detected"** (Activity, Confidence %, Risk level, Location, Timestamp).

2. **False-Positive Control & Temporal Confirmation**:
   - Requires suspicious state to persist for configurable duration (`SUSPICIOUS_CONFIRMATION_SECONDS`, default 1.5s) or consecutive frames before triggering alarms, preventing single-frame false alarms.
   - Configurable sensitivity (`DETECTION_SENSITIVITY`) and confidence threshold (`DETECTION_CONFIDENCE_THRESHOLD`).

3. **Automatic Evidence Recording & Secure Signed Storage**:
   - Automatically records a short 5-8 second evidence video clip upon confirmed incident.
   - Saves evidence clip securely in storage abstraction (`LocalStorageProvider` or `S3StorageProvider`).
   - Generates time-bounded signed video tokens (`create_signed_video_token`), preventing unauthorized scraping of surveillance footage.

4. **Automated SMS Notification Gateway**:
   - Dispatches real-time SMS alerts to Admin phone via background daemon threads.
   - SMS format:
     ```
     ALERT: Suspicious activity detected.
     Activity: Restricted Area Intrusion
     Location: Storage Room Vault
     Time: 10:42:15 AM
     Risk: HIGH
     View evidence:
     https://surveilguard.example.com/?event_id=EVT-0001#view-event-detail
     ```
   - Clicking the SMS link opens the event and plays the evidence video directly in any browser.
   - Cooldown deduplication (`SMS_COOLDOWN_SECONDS`, default 30s) prevents notification spam.
   - Supports Mock provider (local dev), Twilio, Vonage, and generic HTTP webhooks.

5. **Detection Sessions & Admin Auditing**:
   - Every live monitoring session creates a `DetectionSession` associating the Admin name, user ID, camera ID, start/end timestamps, and device info.
   - Immutable security `AuditLog` records logins, detection starts/stops, video processing, reviews, and SMS dispatches.

6. **Reporting & Compliance Export**:
   - Daily, weekly, monthly, and custom date-range activity reports.
   - One-click official CSV export with full event details, risk priorities, and SMS status.

7. **Production Security & RBAC**:
   - PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and random salt.
   - Cryptographically signed JWT bearer tokens.
   - Role-Based Access Control (`admin`, `operator`, `viewer`).
   - Strict upload validation (MIME types, size limits, sanitized filenames, path traversal protection).

---

## 📁 Repository Structure

```
AJ/
├── app/
│   ├── config.py                 # Central configuration loaded from .env
│   ├── database/
│   │   └── connection.py         # SQLAlchemy engine, session maker, auto-migration
│   ├── models/
│   │   ├── schema.py             # User, Camera, Event, DetectionSession, EvidenceVideo, AuditLog, SMSLog, Review
│   │   └── notification_models.py# AdminDevice, Incident, NotificationLog
│   ├── routes/
│   │   ├── auth.py               # JWT login, me, logout, user management
│   │   ├── live_monitoring.py    # Frame detect, sessions start/stop, evidence save, websocket
│   │   ├── videos.py             # Video ingestion, upload security, secure signed streaming
│   │   ├── events.py             # Event listing, filtering, creation
│   │   ├── reviews.py            # Security operator review submission
│   │   ├── reports.py            # Activity reports & CSV download
│   │   ├── sms_routes.py         # SMS test dispatch & delivery logs
│   │   ├── audit_logs.py         # Security audit log ledger
│   │   ├── cameras.py            # Camera CRUD & zone configuration
│   │   └── analytics.py          # Dashboard summary KPIs & charts
│   ├── schemas/
│   │   └── dto.py                # Pydantic DTO validation schemas
│   └── services/
│       ├── auth_service.py       # PBKDF2 hashing, JWT signing, signed video tokens
│       ├── live_detection_service.py # CV inference & false positive confirmation
│       ├── detection_session_service.py # Session lifecycle & tracking
│       ├── storage_service.py    # Storage abstraction & path traversal defense
│       ├── sms_service.py        # SMS gateway (Mock, Twilio, Vonage, Webhook)
│       ├── audit_service.py      # Immutable security audit logger
│       ├── report_service.py     # Activity report & CSV generator
│       └── event_service.py      # Event queries & KPI aggregations
├── data/                         # Persistent operational storage
│   ├── evidence/                 # Secure evidence video clips
│   ├── uploads/                  # Ingested video files
│   ├── thumbnails/               # Generated frame thumbnails
│   ├── sample_videos/            # Benchmark test video scenarios
│   └── surveillance_events.db    # SQLite operational database
├── frontend/
│   ├── index.html                # Mobile-first Admin interface
│   ├── css/style.css             # Responsive layout, dark sidebar, HUD badges
│   └── js/
│       ├── api.js                # REST API client with JWT handling
│       ├── app.js                # Live detection canvas loop, media recorder, view controllers
│       └── charts.js             # Chart.js analytics graphs
├── ml/                           # Machine Learning anomaly detection engine
│   ├── anomaly_detection.py      # Isolation Forest & One-Class SVM models
│   ├── preprocessing.py          # Feature extraction & matrix transformation
│   └── sample_training_data.py   # Baseline training distribution
├── tests/
│   └── test_system.py            # Comprehensive automated test suite (13 test cases)
├── test_pipeline.py              # End-to-end CV/ML pipeline verification
├── requirements.txt              # Project dependencies
├── .env.example                  # Environment configuration template
└── run.py                        # Server runner entrypoint
```

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env` and set your configuration parameters:

```bash
cp .env.example .env
```

Key configuration options:

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://127.0.0.1:8000` | Backend API URL (use HTTPS in production) |
| `FRONTEND_URL` | `http://127.0.0.1:8000` | Frontend web URL (for SMS links) |
| `SECRET_KEY` | *(change in prod)* | Secret key for JWT signing & token verification |
| `JWT_SECRET` | *(change in prod)* | Secret key for JWT access tokens |
| `DATABASE_URL` | `sqlite:///data/surveillance_events.db` | SQLite or PostgreSQL connection string |
| `SMS_PROVIDER` | `mock` | SMS provider: `mock`, `twilio`, `vonage`, `generic_http` |
| `ADMIN_PHONE_NUMBER` | `+1234567890` | Target Admin phone for SMS alerts |
| `SMS_COOLDOWN_SECONDS` | `30` | Cooldown period between SMS alerts per camera |
| `DETECTION_SENSITIVITY` | `0.35` | Detection sensitivity (0.0 to 1.0) |
| `SUSPICIOUS_CONFIRMATION_SECONDS` | `1.5` | Duration suspicious state must persist before alert |
| `STORAGE_PROVIDER` | `local` | `local` for filesystem or `s3` for object storage |

### Email Alerts

Set `RESEND_API_KEY` in the environment and configure `ADMIN_EMAILS` as a
comma-separated list of admin addresses. The legacy `ADMIN_EMAIL` remains
supported and is combined with `ADMIN_EMAILS` and active database-managed
recipients; duplicate addresses are collapsed. `ALERT_FROM_EMAIL` takes
precedence over the legacy `EMAIL_FROM`.

Resend's `onboarding@resend.dev` sandbox sender is restricted to the verified
Resend account owner and cannot deliver to arbitrary recipients. To send to
multiple admins, verify a domain in Resend and use a sender on that domain, for
example `alerts@your-verified-domain.com`.

Local storage remains usable on the machine running the application. Emails do
not include localhost URLs, direct file paths, or public thumbnail links. To
include remote review links, configure `APP_BASE_URL`/`PUBLIC_BASE_URL` and
`BASE_URL` with publicly reachable HTTPS application/API URLs. Evidence video
links use the existing time-limited signed stream endpoint; the deployed API
must be reachable over HTTPS and have access to the local evidence files, or
use configured object storage.

---

## 🚀 Running Locally

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Seed Database & Generate Baseline Models
```bash
python scripts/seed_database.py
```

### 3. Start the Server
```bash
python run.py
```
Or directly with uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Open in Browser
- **Admin Dashboard**: `http://127.0.0.1:8000`
- **Interactive Swagger API Docs**: `http://127.0.0.1:8000/docs`

**Default Credentials**:
- **Admin**: Username: `admin` / Password: `admin123`
- **Operator**: Username: `operator` / Password: `operator123`

---

## 📱 Mobile Camera Access & HTTPS Requirements

Modern mobile browsers (Chrome on Android, Safari on iOS) require **HTTPS** (or `localhost`) to grant `navigator.mediaDevices.getUserMedia` camera permissions.

### Testing on Local Network / Phone
To test live camera detection from your phone on local Wi-Fi:
1. Use an HTTPS tunneling tool such as `ngrok` or `cloudflared`:
   ```bash
   ngrok http 8000
   ```
2. Update `BASE_URL` and `FRONTEND_URL` in `.env` with your HTTPS ngrok URL:
   ```env
   BASE_URL=https://your-tunnel.ngrok-free.app
   FRONTEND_URL=https://your-tunnel.ngrok-free.app
   ```
3. Open the HTTPS URL in your mobile browser, log in, grant camera permission, and tap **START DETECTION**!

---

## 🧪 Automated Testing

Run the comprehensive automated test suite:
```bash
python -m unittest tests/test_system.py
```

Run the video processing pipeline test on sample benchmark videos:
```bash
python test_pipeline.py
```

---

## 🌐 Production Deployment Guide

### 1. Production Database (PostgreSQL)
Set `DATABASE_URL` in `.env`:
```env
DATABASE_URL=postgresql://surveil_user:SecurePassword123@db-host:5432/surveilguard_prod
```
The application automatically runs schema initialization and column migrations on startup.

### 2. Twilio SMS Setup
```env
SMS_PROVIDER=twilio
SMS_API_KEY=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SMS_API_SECRET=your_twilio_auth_token
SMS_SENDER=+18005550199
ADMIN_PHONE_NUMBER=+1234567890
```

### 3. Running with Gunicorn / Uvicorn Workers
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### 4. Reverse Proxy & SSL (Nginx)
```nginx
server {
    listen 443 ssl http2;
    server_name surveilguard.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/surveilguard.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/surveilguard.yourdomain.com/privkey.pem;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 🔒 Security Best Practices

1. **Private Video Storage**: Surveillance footage is never exposed through permanent public URLs. Video streams are protected with signed JWT tokens (`/api/videos/secure-stream/{id}?token=...`).
2. **Path Traversal Protection**: Uploaded filenames are sanitized and stored using randomized UUIDs outside source directories.
3. **Audit Trails**: Security compliance logs record actor IDs, IP addresses, user-agents, and timestamps for all administrative actions.
4. **Password Security**: Passwords use PBKDF2-HMAC-SHA256 with 100,000 iterations and unique cryptographic salts.
