# HACKFIX AI — Full-Stack Website Security Scanner Engine

> **Non-Destructive Web Application Vulnerability Auditor with Evidence-Based Retesting & Gemini AI Explanations**

HACKFIX AI is an application security audit platform built to help software engineers discover, understand, and remediate website security weaknesses before attackers exploit them.

---

## 1. Product Workflow

```
SCAN ➔ FIND ➔ PROVE ➔ EXPLAIN ➔ FIX ➔ RETEST
```

1. **SCAN**: Validates target authorization and enforces strict outbound SSRF network boundaries.
2. **FIND**: Discovers live endpoints and executes non-destructive security checks (HTTP headers, SSL/TLS certificates, cookie flags, CORS configuration, information disclosure, and public resource probes).
3. **PROVE**: Collects and structures concrete HTTP response evidence, status codes, and header signatures. Never fabricates alerts.
4. **EXPLAIN**: Translates technical security findings into beginner-friendly explanations with Google Gemini (or deterministic security engine fallback).
5. **FIX**: Generates actionable code remediations (before/after code diffs for Nginx, Apache, Express, FastAPI, and Next.js).
6. **RETEST**: Re-executes the exact verification check against the target to prove whether a vulnerability is **Verified Fixed** or **Still Present**.

---

## 2. Technology Stack

- **Frontend**: Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS, Lucide Icons.
- **Backend**: Python 3.11+, FastAPI, Uvicorn, Pydantic v2, HTTPX, SQLAlchemy (Async), aiosqlite (SQLite).
- **AI Integration**: Official `google-genai` Python SDK (`from google import genai`) with prompt sanitization and deterministic fallback templates.
- **Reporting Engine**: ReportLab (vector PDF generation) & responsive HTML exports.
- **Testing**: Pytest & pytest-asyncio with 22+ automated tests.
- **Optional ZAP**: OWASP ZAP Baseline scanner integration.

---

## 3. Architecture & Project Layout

```
hackfix-ai/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI route controllers (scan, history, chat, retest, report, health)
│   │   ├── core/            # Config (settings), async database session, security constants
│   │   ├── models/          # SQLAlchemy persistent models (Scan, Finding, ScanLog, RetestHistory)
│   │   ├── schemas/         # Pydantic validation schemas
│   │   ├── scanner/
│   │   │   ├── ssrf_validator.py       # SSRF protection, IP/DNS validation, safe redirect transport
│   │   │   ├── crawler.py              # Bounded same-origin crawler (max 25 pages, depth 2)
│   │   │   ├── engine.py               # 4-stage pipeline orchestrator (FIND->PROVE->FIX->VERIFY)
│   │   │   └── modules/                # Security inspection modules
│   │   │       ├── headers.py          # CSP, HSTS, X-Content-Type-Options, X-Frame-Options
│   │   │       ├── tls_check.py        # Certificate validity, expiration, cleartext HTTP detection
│   │   │       ├── cookies.py          # Secure, HttpOnly, SameSite attribute analysis
│   │   │       ├── info_disclosure.py  # Server banners, stack trace and exception leakage
│   │   │       ├── exposed_resources.py# .env, .git, robots.txt, OpenAPI public probes
│   │   │       ├── cors_check.py       # CORS origin reflection & wildcard credentials
│   │   │       └── zap_integrator.py   # Optional OWASP ZAP Baseline runner & parser
│   │   └── services/
│   │       ├── gemini_service.py       # Official Google GenAI client & deterministic fallback
│   │       ├── report_service.py       # ReportLab PDF & HTML report generator
│   │       └── retest_service.py       # Evidence comparison engine for individual finding retesting
│   ├── test_target/
│   │   └── target_app.py    # Deliberately vulnerable local test server (Port 8001) with live toggle
│   ├── tests/               # Pytest automated test suite
│   ├── requirements.txt     # Backend Python dependencies
│   └── pytest.ini           # Pytest test configuration
├── frontend/
│   ├── app/
│   │   ├── page.tsx         # Executive Security Dashboard (metrics from stored scans)
│   │   ├── new-scan/        # Scan launcher with URL validation and authorization consent
│   │   ├── scan/[id]/       # Live scan pipeline, timestamped logs, expandable findings
│   │   ├── findings/        # Aggregated findings directory with severity & OWASP filters
│   │   ├── history/         # Persistent SQLite scan history with deletion & inspection
│   │   ├── reports/         # PDF and HTML report download center
│   │   └── settings/        # System capabilities, AI status, and SSRF configuration
│   ├── components/          # Sidebar, Navbar, SeverityBadge, OwaspCoverageTable, AiChatDrawer, RetestModal
│   ├── lib/                 # Typed API client and TypeScript definitions
│   └── package.json         # Frontend Node dependencies
├── run.ps1                  # 1-click startup script for Windows
├── run.sh                   # 1-click startup script for Linux/macOS
├── .env.example             # Environment template
└── README.md
```

---

## 4. Quick Start Guide

### Prerequisites
- Python 3.11 or higher
- Node.js 18 or higher (v20+ recommended)
- Git (optional)

### Setup Backend (Python)
```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Setup Frontend (Next.js)
```bash
cd ../frontend

# Install frontend packages
npm install
```

---

## 5. Running the Application

### Option A: Using Startup Scripts
- **Windows**:
  ```powershell
  .\run.ps1
  ```
- **Linux / macOS**:
  ```bash
  chmod +x run.sh
  ./run.sh
  ```

### Option B: Running Manually (3 Terminals)

**Terminal 1 — Deliberately Vulnerable Test Target (Port 8001):**
```bash
cd backend
.\.venv\Scripts\python -m uvicorn test_target.target_app:app --host 127.0.0.1 --port 8001
```

**Terminal 2 — HACKFIX AI Backend (Port 8000):**
```bash
cd backend
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 3 — HACKFIX AI Frontend (Port 3000):**
```bash
cd frontend
npm run dev
```

Open your browser to: **`http://localhost:3000`**

---

## 6. Testing with the Built-In Vulnerable Target

To safely demonstrate HACKFIX AI without scanning external websites:

1. Click **"New Scan"** in the sidebar.
2. Click the shortcut **"Use Local Test Application (port 8001)"** or enter `http://localhost:8001/`.
3. Check the **Authorization Acknowledgement** checkbox and click **Start Security Scan**.
4. Watch the live 4-stage pipeline:
   - **FIND**: Discovers missing CSP, HSTS, X-Content-Type-Options, cookie missing HttpOnly/Secure flags, exposed `Server: InsecureDemoServer` banner, and robots.txt disallows.
   - **PROVE**: Evaluates actual headers and HTTP responses.
   - **FIX**: Prepares before/after code remediation blocks and Gemini explanations.
   - **VERIFY**: Establishes retest baseline.
5. In the findings list, click **"Retest Fix"** on any finding (e.g., Missing Content-Security-Policy). It will show **STILL PRESENT**.
6. Switch the target application into hardened mode by clicking its toggle or issuing:
   ```bash
   curl -X POST http://127.0.0.1:8001/toggle-fix
   ```
7. Click **"Run Retest"** again in the HACKFIX AI UI. The finding will immediately update to **VERIFIED FIXED**!

---

## 7. Configuring Google Gemini AI

HACKFIX AI uses the official `google-genai` Python SDK (`from google import genai`).

### Adding an API Key:
Create or edit `backend/.env`:
```env
GEMINI_API_KEY="AIzaSyYourGeminiApiKeyHere"
GEMINI_MODEL="gemini-2.5-flash"
GEMINI_ENABLED=true
```

### What works without Gemini:
If `GEMINI_API_KEY` is not provided:
- The entire scanner engine continues to work with **100% full fidelity**.
- All security headers, certificates, cookies, CORS, and info disclosure checks run normally.
- PDF reports, HTML reports, and retesting work completely.
- Findings and contextual chat use HACKFIX AI's **deterministic security guidance engine** to provide structured beginner explanations and remediation steps.

---

## 8. OWASP ZAP Baseline Integration

OWASP ZAP Baseline integration is **optional and disabled by default** (`ZAP_ENABLED=false`).

### Enabling ZAP Baseline:
1. Ensure Docker is installed and running, or install `zap-baseline.py` locally.
2. Edit `backend/.env`:
   ```env
   ZAP_ENABLED=true
   ZAP_USE_DOCKER=true
   ZAP_DOCKER_IMAGE="zaproxy/zap-baseline:latest"
   ```
3. When enabled, HACKFIX AI invokes `zap-baseline.py` in passive crawler mode, captures the structured JSON report, normalizes alerts into the HACKFIX finding schema, and deduplicates them against native checks.
4. If ZAP is missing or disabled, the application displays the limitation honestly and native checks continue seamlessly.

---

## 9. SSRF and URL Safety Controls

HACKFIX AI makes outbound HTTP requests to user-specified URLs. To eliminate Server-Side Request Forgery (SSRF) and egress attacks:
- **Strict Scheme Enforcement**: Only `http://` and `https://` are permitted. Schemes such as `ftp://`, `file://`, and `gopher://` are rejected.
- **Embedded Credentials Blocked**: URLs like `http://user:pass@host` are rejected.
- **DNS Resolution Pre-Check**: Resolves all hostnames and inspects every resolved IP address using Python's `ipaddress` module.
- **Private Subnet & Metadata Isolation**: Loopback (`127.0.0.0/8`, `::1`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata (`169.254.169.254`, `metadata.google.internal`) are blocked by default.
- **Development Allowlist**: Authorized local testing hostnames (`localhost`, `127.0.0.1`) are permitted only via explicit configuration in `SCAN_ALLOWED_HOSTS`.
- **Redirect Revalidation**: Custom `SafeAsyncHttpClient` catches 3xx HTTP redirects and re-validates the destination URL against all SSRF controls on every hop before connecting.

---

## 10. OWASP Top 10:2025 Coverage

HACKFIX AI maps findings against the official **OWASP Top 10:2025** categories:

| Category | Description | Passive Audit Capability | Coverage Status |
|---|---|---|---|
| **A01** | Broken Access Control | Observable URL routes, CORS reflection | `findings_present` / `assessment_limited` |
| **A02** | Security Misconfiguration | Headers, banners, default resources | `findings_present` / `no_findings_detected` |
| **A03** | Software Supply Chain Failures | Manifests and SBOMs required | `not_assessed` |
| **A04** | Cryptographic Failures | TLS validity, expired certs, HSTS | `findings_present` / `no_findings_detected` |
| **A05** | Injection | Requires active attack vectors | `not_assessed` |
| **A06** | Insecure Design | Requires architecture review | `not_assessed` |
| **A07** | Authentication Failures | Cookie flags assessed (HttpOnly/Secure) | `findings_present` / `assessment_limited` |
| **A08** | Integrity Failures | Subresource Integrity (SRI) | `assessment_limited` |
| **A09** | Logging & Alerting Failures | Internal SIEM logs not observable | `not_assessed` |
| **A10** | Exceptional Conditions | Unhandled debug traces & stack traces | `findings_present` / `assessment_limited` |

> *Note: "No findings detected" means only that configured passive checks did not detect an issue; it does not guarantee the target is immune to vulnerabilities.*

---

## 11. Automated Testing

Run the full automated test suite using pytest:

```bash
cd backend
.\.venv\Scripts\pytest -v
```

All 22 unit and integration tests verify:
- Scheme validation and SSRF defenses.
- Rejection of embedded credentials and cloud metadata IP addresses.
- Redaction of sensitive API keys and tokens.
- Security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
- Cookie attributes (Secure, HttpOnly, SameSite).
- Server banner and stack trace information disclosure detection.
- OWASP Top 10:2025 taxonomy mapping.
- Gemini fallback explanations and chat responses without an API key.
- ZAP alert normalization and disabled status.
- ReportLab vector PDF report generation.
- FastAPI endpoint contracts and error handling.

---

## 12. Troubleshooting

| Issue | Cause | Resolution |
|---|---|---|
| **Port 8000 already in use** | Another FastAPI instance is running | Terminate the process using port 8000 or run on `--port 8002` and update `frontend/next.config.mjs`. |
| **SSRF error when scanning localhost** | `SCAN_ALLOWED_HOSTS` does not include hostname | Ensure `localhost` and `127.0.0.1` are in `SCAN_ALLOWED_HOSTS` in `backend/.env`. |
| **Gemini responses show "Fallback Engine"** | `GEMINI_API_KEY` is not set or invalid | Set your Google GenAI key in `backend/.env`. The application continues to function normally using deterministic templates. |
| **PDF download fails** | Missing ReportLab dependency | Run `pip install reportlab>=4.1.0` in the backend virtual environment. |

