# SCAMGUARD AI — Social Media Scam Detection System
> **BCA Final-Year Capstone Project — Cybersecurity & Artificial Intelligence**
> **GitHub Repository**: [Mrgowda631/SCAMGUARD-AI](https://github.com/Mrgowda631/SCAMGUARD-AI)

[![GitHub Repo](https://img.shields.io/badge/GitHub-SCAMGUARD--AI-181717?style=flat&logo=github&logoColor=white)](https://github.com/Mrgowda631/SCAMGUARD-AI)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React%2018-20232A?style=flat&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat&logo=vite&logoColor=white)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-38B2AC?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Node.js](https://img.shields.io/badge/Node.js%2024-43853D?style=flat&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express.js-000000?style=flat&logo=express&logoColor=white)](https://expressjs.com/)
[![Google Gemini API](https://img.shields.io/badge/Google%20Gen%20AI-4285F4?style=flat&logo=google&logoColor=white)](https://ai.google.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)](https://www.sqlite.org/)

---

## 1. Project Overview

**SCAMGUARD AI** is a production-minded, full-stack Security Operations Center (SOC) web application built to combat the escalating threat of cyber fraud, social engineering, impersonation, phishing, cryptocurrency doubling scams, and fraudulent recruitment campaigns across digital platforms.

Designed specifically as a capstone project for **BCA Final-Year Cybersecurity and Artificial Intelligence**, this system pairs high-speed deterministic heuristic pattern engines with cloud-backed reasoning using the **Google Gemini API** (`@google/genai`).

### Key Capabilities
- **Message & Content Scanner**: Forensic analysis of SMS (smishing), WhatsApp forwards, spear-phishing emails, direct messages, and recruitment solicitations.
- **URL Security Scanner**: Structural URL decomposition, brand lookalike/typosquatting detection (e.g. `paypa1`, `arnazon`), high-risk TLD filtering, raw IP host identification, and strict **Server-Side Request Forgery (SSRF)** loopback barriers.
- **Social Media Post Analyzer**: Dedicated triage for Instagram, X / Twitter, Telegram, Facebook, and LinkedIn content.
- **Persistent Forensic History**: Account-isolated SQLite database tracking all historical scans, risk scores, extracted indicators, and remediation steps.
- **Forensic Threat Reports**: Formal downloadable TXT & JSON dossiers featuring standardized report identifiers (`SGR-2026-XXXX`) with print-optimized layouts.
- **Threat Analytics Dashboard**: Interactive Recharts visualizations displaying 7-day scan trends, risk distribution donut charts, and attack category distributions.
- **Scam Awareness Hub**: Educational repository detailing 8 attack vectors, 5 golden rules of cyber defense, and an interactive scored defense quiz.
- **Role-Based SOC Administration**: Protected administrative interface with platform-wide user lists, scan telemetry, system audit logs, and server health telemetry.

---

## 2. System Architecture

```
                     +-------------------------------------------------+
                     |                 ANALYST BROWSER                 |
                     |   React 18 + Vite + TailwindCSS + Recharts      |
                     +-------------------------------------------------+
                                      |             ^
             HTTP / Session Cookies   |             |  JSON Responses
             (Credentials: 'include') |             |
                                      v             |
                     +-------------------------------------------------+
                     |               EXPRESS BACKEND (SOC)             |
                     |                 Port 8000 (Node.js)             |
                     +-------------------------------------------------+
                       |         |                |                  |
                       |         |                |                  |
                       v         v                v                  v
                 +----------+ +-----------+ +------------+    +---------------+
                 |  Helmet  | | Auth &    | |  SSRF &    |    | Deterministic |
                 |  & CORS  | | RateLimit | | URL Engine |    | Heuristic Mod |
                 +----------+ +-----------+ +------------+    +---------------+
                                      |                              |
                                      +-------------+----------------+
                                                    |
                                      (If Key Configured & Online)
                                                    v
                                      +-------------------------------+
                                      |     GOOGLE GEMINI AI API      |
                                      |     Model: gemini-3.8-flash   |
                                      |      (@google/genai SDK)      |
                                      +-------------------------------+
                                                    |
                                                    v
                                      +-------------------------------+
                                      |     SQLITE DATABASE (WAL)     |
                                      |  Users, Sessions, Scans, Logs |
                                      +-------------------------------+
```

---

## 3. Strict Gemini API Security Directives

1. **Zero Client-Side Exposure**: The `GEMINI_API_KEY` is exclusively read from the backend process environment (`process.env.GEMINI_API_KEY`). It is **never** bundled in frontend scripts, Vite build outputs, HTML templates, or Git commits.
2. **Backend Proxy Pattern**: The client never calls Google directly. All calls flow through authenticated backend endpoints (`POST /api/detect`, `POST /api/detect-url`, `POST /api/detect-social`).
3. **Prompt Injection Hardening**: All user inputs are wrapped with strict system directives specifying that submitted content is **UNTRUSTED TELEMETRY** and must never be interpreted as instructions.
4. **Resilient Heuristic Fallback**: If the Gemini API key is missing, network access is restricted, or API quotas are exceeded, the system automatically engages the built-in deterministic heuristic engine. Results explicitly tag `engine: "gemini"` or `engine: "heuristic_fallback"` to maintain total transparency.

---

## 4. Prerequisites

- **Node.js**: `v20.0.0` or higher (tested on Node.js `v24.19.0`)
- **npm**: `v10.0.0` or higher (tested on npm `v11.17.0`)
- **Google Gemini API Key** (optional for AI mode; offline heuristic mode operates without keys): [Get API Key from Google AI Studio](https://aistudio.google.com/)

---

## 5. Installation & Setup

### Step 1: Clone or Navigate to the Project Root
```bash
cd nandan
```

### Step 2: Install Monorepo Dependencies
```bash
npm install
```
This automatically provisions dependencies across both the Express backend (`server/`) and the React client (`client/`).

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env` in the project root:
```bash
cp .env.example .env
```
*(On Windows PowerShell, use: `Copy-Item .env.example .env`)*

Configure your environment settings:
```ini
# Server Port
PORT=8000

# Node Environment
NODE_ENV=development

# Frontend Dev URL (for CORS and cookies)
FRONTEND_ORIGIN=http://localhost:8080

# Session encryption secret (32+ character random string)
SESSION_SECRET=your_long_random_session_secret_scamguard_2026

# Google Gemini API Key
GEMINI_API_KEY=your_actual_gemini_api_key_here

# Active Model (gemini-3.8-flash recommended)
GEMINI_MODEL=gemini-3.8-flash

# SQLite Database Location
DATABASE_URL=./scamguard.db

# Initial Administrator Credentials
ADMIN_NAME="System Administrator"
ADMIN_EMAIL=shreyasc299@gmail.com
ADMIN_PASSWORD=Shreyas@631
```

---

## 6. Password Security Policy

SCAMGUARD AI enforces an enterprise-grade password security policy across User Registration, Analyst Login, and Profile Password Rotation:

- **Length Constraints**: Minimum 8 characters, maximum 64 characters.
- **Complexity Requirements**:
  - At least one uppercase letter (`[A-Z]`)
  - At least one lowercase letter (`[a-z]`)
  - At least one numeric digit (`[0-9]`)
  - At least one special symbol (`[!@#$%^&*()_+-=[]{}|;:,.<>?]`)
- **Explicit Rejections**:
  - Passwords consisting only of words or names (e.g., `"Sanjay Kumar"`) are rejected with `HTTP 400`.
  - Passwords consisting only of numbers (e.g., `"12345678"`) are rejected with `HTTP 400`.
  - Common trivial dictionary patterns (e.g., `password123!`, `admin123!`) are rejected.
- **Frontend Real-Time Evaluation**: Dynamic 4-point visual checklist and colored password strength meter bar in `client/src/pages/Register.tsx`.

---

## 7. Database Initialization & Admin Setup

SCAMGUARD AI includes a command-line administrator bootstrap script that creates the SQLite schema in Write-Ahead Logging (WAL) mode and seeds the super administrator account with a bcrypt-hashed password:

```bash
npm run seed:admin
```

Output:
```
--- SCAMGUARD AI Administrator Account Initialization ---
Successfully created administrator [shreyasc299@gmail.com]
Admin account initialization completed successfully.
```

Default administrator credentials:
- **Email**: `shreyasc299@gmail.com`
- **Password**: `Shreyas@631`

---

## 8. Running the Application

### Option A: One-Click Startup Script (Windows)
Double-click `start.bat` or run from PowerShell:
```cmd
.\start.bat
```
This automatically verifies dependencies, starts the Express SOC backend (port 8000), launches the Vite frontend (port 8080), activates backward-compatibility port bridges (ports 5173 and 3000 -> 8080), and opens your default browser.

### Option B: Monorepo Dev Command
```bash
npm run dev
```
- **Backend API**: Running at `http://localhost:8000`
- **Frontend SOC Dashboard**: Running at `http://localhost:8080`
- **Port Compatibility Bridges**: Automatically redirects ports `5173` and `3000` to `8080` for seamless access.

---

## 9. Automated Testing & Verification

The project includes an end-to-end automated test suite covering:
- **Context-Aware AI Accuracy Benchmark**: 27 real-world test cases including harmless college chats, urgent smishing, fake job recruitment fees, crypto doubling, military credential requests, security class discussions, and typosquatting.
- **Password Security & RBAC**: Strict rejection of weak passwords ("Sanjay Kumar", numeric-only), password complexity verification, session cookies, and 403 access control.
- **URL Security & SSRF Guard**: Private RFC 1918 range blocking, loopback defense (`127.0.0.1`, `localhost`), and typosquatting detection.
- **Cross-User Data Isolation**: Verification that users cannot access or alter foreign scan records.

To execute the full test suite:
```bash
npm test
```

Test Results Summary:
```
 ✓ tests/auth.test.ts (11 tests)
 ✓ tests/accuracy.test.ts (27 tests)
 ✓ tests/detect.test.ts (6 tests)
 ✓ tests/urlAnalyzer.test.ts (9 tests)
 ✓ tests/heuristic.test.ts (4 tests)

 Test Files  5 passed (5)
      Tests  57 passed (57)
```

---

## 10. Production Build

To compile both the server TypeScript and the optimized Vite React production bundle:
```bash
npm run build
```
- **Backend output**: `server/dist/`
- **Frontend output**: `client/dist/`

To start the production server:
```bash
cd server && npm start
```

---

## 11. API Reference Documentation

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/health` | Public | System status, Gemini AI state, and active model |
| `GET` | `/api/settings/info` | Public | Model details, risk thresholds, and 2FA status |
| `POST` | `/api/auth/register` | Public | Register new analyst account |
| `POST` | `/api/auth/login` | Public | Authenticate analyst and set HTTP-only cookie |
| `POST` | `/api/auth/logout` | Authenticated | Revoke session and clear cookie |
| `GET` | `/api/auth/me` | Authenticated | Get current analyst profile |
| `POST` | `/api/auth/change-password` | Authenticated | Change password and revoke other sessions |
| `GET` | `/api/auth/sessions` | Authenticated | List all active sessions for current user |
| `POST` | `/api/detect` | Authenticated | Scan SMS, email, WhatsApp, or post text |
| `POST` | `/api/detect-url` | Authenticated | Scan URL for typosquatting, SSRF, and risky TLDs |
| `POST` | `/api/detect-social` | Authenticated | Scan Instagram, Twitter, Telegram, LinkedIn posts |
| `GET` | `/api/scans` | Authenticated | List, filter, sort, and paginate user scans |
| `GET` | `/api/scans/:id` | Authenticated | Get single scan record details |
| `DELETE`| `/api/scans/:id` | Authenticated | Delete single scan record |
| `GET` | `/api/scans/export/csv` | Authenticated | Stream user scan history as CSV file |
| `GET` | `/api/scans/export/json` | Authenticated | Export user scan history as JSON array |
| `GET` | `/api/analytics` | Authenticated | Telemetry metrics, 7-day trends, category counts |
| `GET` | `/api/reports/:id` | Authenticated | Generate forensic report (JSON or formatted TXT) |
| `GET` | `/api/admin/overview` | Admin Only | Platform-wide user counts, scan ratios, audit logs |
| `GET` | `/api/admin/users` | Admin Only | Sanitized user accounts list with scan counts |
| `GET` | `/api/admin/audit-logs` | Admin Only | System security audit trail |

---

## 12. Security Limitations & Forensic Disclaimer

- **Automated Advisory Tool**: SCAMGUARD AI is an automated threat intelligence system designed for triage and educational defense. Reports produced by the system are automated evaluations and do not constitute certified judicial forensic affidavits.
- **SSRF & Sandboxing**: To protect hosting infrastructure and prevent server takeover, the URL scanner does not execute live outbound HTTP web scraping or run untrusted executable attachments.
- **Pasted Social Content**: Analysis of social media content evaluates the submitted textual and visual claims. It does not access private platform APIs or definitively prove bot automation.

---

## 13. Project Structure

```
nandan/
├── .env.example              # Template environment configuration
├── .gitignore                # Excludes secrets, databases, and dependencies
├── README.md                 # Complete documentation & run guide
├── package.json              # Monorepo orchestration scripts
├── server/
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts          # Express server entrypoint & middleware
│   │   ├── config.ts         # Environment settings & secrets loader
│   │   ├── db/
│   │   │   └── database.ts   # Node 24 native SQLite (DatabaseSync, WAL)
│   │   ├── middleware/
│   │   │   ├── auth.ts       # Session cookies, bcrypt, and RBAC
│   │   │   ├── rateLimiter.ts# Endpoint brute-force protection
│   │   │   └── errorHandler.ts # Sanitized error responses
│   │   ├── routes/
│   │   │   ├── auth.ts       # Registration, login, logout, password
│   │   │   ├── detect.ts     # Content, URL, and social detection APIs
│   │   │   ├── scans.ts      # Scan history CRUD, pagination, exports
│   │   │   ├── analytics.ts  # Database-driven metrics for Recharts
│   │   │   ├── reports.ts    # Forensic dossier generator & download
│   │   │   └── admin.ts      # Privileged administrative endpoints
│   │   ├── services/
│   │   │   ├── gemini.ts     # Official Google Gen AI SDK integration
│   │   │   ├── heuristic.ts  # Deterministic offline heuristic engine
│   │   │   └── urlAnalyzer.ts# SSRF protection, brand typosquatting
│   │   └── scripts/
│   │       └── seedAdmin.ts  # Secure CLI admin bootstrap script
│   └── tests/
│       ├── auth.test.ts      # Authentication & RBAC tests
│       ├── detect.test.ts    # Threat scanning & cross-user isolation
│       ├── heuristic.test.ts # Heuristic rule verification
│       └── urlAnalyzer.test.ts # SSRF and typosquatting tests
└── client/
    ├── package.json
    ├── vite.config.ts        # Vite configuration with /api proxy
    ├── tailwind.config.js    # Cybersecurity dark theme & tokens
    ├── postcss.config.js
    ├── index.html            # Inter & JetBrains Mono typography
    └── src/
        ├── index.css         # Glassmorphism, cyber grid, scrollbars
        ├── main.tsx          # React 18 mount entrypoint
        ├── App.tsx           # React Router v6 & protected layouts
        ├── types/            # TypeScript interfaces
        ├── services/api.ts   # Type-safe API client (credentials: include)
        ├── context/
        │   ├── AuthContext.tsx  # User state & authentication handler
        │   └── ToastContext.tsx # Notification alerts system
        ├── components/
        │   ├── Navbar.tsx       # Top bar with Gemini status indicator
        │   ├── Sidebar.tsx      # Persistent SOC navigation menu
        │   ├── ThreatGauge.tsx  # Circular SVG risk score gauge
        │   ├── ThreatBadge.tsx  # Color-coded threat classification badge
        │   ├── StatCard.tsx     # SOC telemetry card
        │   ├── AnalysisResultCard.tsx # Threat findings & recommendations
        │   ├── Toast.tsx        # Toast alerts
        │   └── Modal.tsx        # Accessible dialog wrapper
        └── pages/
            ├── Overview.tsx         # Security Operations Dashboard
            ├── ContentScanner.tsx   # Message & Content Scanner
            ├── UrlScanner.tsx       # URL Security Scanner & SSRF Guard
            ├── SocialAnalyzer.tsx   # Social Media Post Analyzer
            ├── ScanHistory.tsx      # Scan history with search & CSV/JSON export
            ├── ThreatAnalytics.tsx  # Recharts graphs & distribution charts
            ├── ForensicReports.tsx  # Reports repository
            ├── ReportDetail.tsx     # Printable forensic threat dossier
            ├── AwarenessHub.tsx     # 8 attack vectors & interactive quiz
            ├── Profile.tsx          # Analyst profile & active session manager
            ├── Settings.tsx         # Engine status & risk thresholds
            ├── AdminDashboard.tsx   # Super Admin Operations Center
            ├── Login.tsx            # Secure analyst sign-in
            └── Register.tsx         # New analyst onboarding
```
