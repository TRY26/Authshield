# AuthShield 🛡️
### Production-Grade CIAM Authentication Engine & Security Playground

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248.svg?style=flat&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![OAuth2](https://img.shields.io/badge/OAuth2-RFC_6749-orange.svg?style=flat)](https://datatracker.ietf.org/doc/html/rfc6749)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AuthShield** is an enterprise-grade Customer Identity and Access Management (CIAM) backend built with **FastAPI** and **MongoDB**. Designed following OWASP security standards and RFC 6749 specifications, AuthShield features cryptographic password hashing, strict token lifecycle management with **Refresh Token Rotation (RTR)**, **Token Theft Reuse Detection**, defensive **API Rate Limiting** against credential stuffing, and a built-in **Interactive Security Playground UI**.

---

## 🌟 Key Architecture & Security Features

### 🔄 1. OAuth2 / RFC 6749 Refresh Token Rotation (RTR)
* **Zero Persistent Tokens:** Access tokens are short-lived (15 minutes). When refreshed via `/refresh`, the presented refresh token is immediately revoked, and a fresh access + refresh token pair is issued.
* **Automated Token Theft & Reuse Detection:** If an already-rotated or revoked refresh token is submitted, AuthShield detects a replay attack and immediately revokes **all** active sessions for that user to prevent session hijacking.

### ⚡ 2. Defensive Rate Limiting (Brute-Force & Credential Stuffing Defense)
* Integrated IP-based rate limiting via **SlowAPI**:
  * `/login`: `5 requests/minute` (prevents brute-force dictionary attacks).
  * `/forgot`: `3 requests/minute` (prevents password recovery spamming).
  * `/signup`: `10 requests/minute` (mitigates automated bot registrations).
* Returns RFC-compliant `HTTP 429 Too Many Requests` with automatic lockout handling.

### 🔒 3. 12-Factor Secrets & Environment Management
* Strict separation of code and config via `config.py` and `.env.example`.
* Zero hardcoded credentials or JWT keys checked into version control.
* Resilient configuration loading with automatic fallback mechanisms.

### ⏱️ 4. Time-Bound, Single-Use Password Recovery
* Generates cryptographic, single-use password reset tokens with a strict **15-minute TTL**.
* Automatically invalidates previous reset tokens upon issuance and immediately consumes the token upon password update to eliminate replay attacks.

### 🛡️ 5. Role-Based Access Control (RBAC) & Account Lockout
* Multi-tier role permissions (`user`, `admin`).
* Automatic account lockout after **3 consecutive failed login attempts**.
* Administrative unlock API (`/admin/unlock/{user_id}`).

### 🖥️ 6. Built-In Interactive Security Playground UI
* Built with **HTML5 + Tailwind CSS** and served directly from FastAPI at `/` or `/demo`.
* **Live Token Inspector:** Decodes signed JWT access tokens and shows claims in real-time.
* **Live RTR Visualizer:** Step through token rotation with animated status indicators.
* **Token Theft Replay Simulator:** Simulates a token replay attack to trigger automated security revocations live on screen.
* **Rate Limiter Burst Tester:** Triggers the SlowAPI rate limiter with rapid request bursts.

---

## 📁 Repository Structure

```text
authproject/
│
├── config.py            # Centralized 12-Factor environment configuration
├── database.py          # Resilient MongoDB client & collection managers
├── auth.py              # Cryptographic helpers, Bcrypt hashing, timezone-aware JWT
├── schemas.py           # Pydantic models with password complexity validation
├── main.py              # FastAPI application, SlowAPI rate limiting, RTR logic, UI routes
├── static/
│   └── index.html       # Single-Page Interactive Security Playground
├── .env.example         # Version-controlled configuration template
├── requirements.txt     # Production dependencies
└── README.md            # Comprehensive project documentation
```

---

## 🚀 Quick Start & Installation

### 1. Clone & Set Up Virtual Environment

```bash
# Clone the repository
git clone https://github.com/TRY26/Authshield.git
cd Authshield

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the template `.env.example` to `.env`:

```bash
cp .env.example .env
```

Update `.env` with your MongoDB connection string and JWT secret:

```env
MONGO_URL=mongodb+srv://<username>:<password>@cluster.mongodb.net/?appName=authshield
MONGO_DB_NAME=auth_project
SECRET_KEY=generate_a_random_32_byte_hex_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
RESET_TOKEN_EXPIRE_MINUTES=15
```

### 3. Run the Application

```bash
uvicorn main:app --reload
```

The application will be available at your local host:
* **Interactive Security Playground:** `http://127.0.0.1:8000/` (or your local host)
* **Interactive Swagger UI:** `http://127.0.0.1:8000/docs`
* **Health Check Probe:** `http://127.0.0.1:8000/health`

---

## 📖 API Endpoint Specifications

| Method | Endpoint | Description | Rate Limit | Auth Required |
| :--- | :--- | :--- | :--- | :--- |
| **GET** | `/` | Serves Interactive Security Playground | Default | No |
| **GET** | `/health` | Health check & database connection probe | Default | No |
| **POST** | `/signup` | Registers new user with password validation | `10/min` | No |
| **POST** | `/login` | Authenticates user; issues access + refresh tokens | `5/min` | No |
| **POST** | `/refresh` | Executes Refresh Token Rotation (RTR) | `20/min` | No |
| **POST** | `/logout` | Blacklists access token & revokes refresh tokens | Default | Bearer JWT |
| **GET** | `/profile` | Retrieves authenticated user profile & claims | Default | Bearer JWT |
| **POST** | `/forgot` | Issues single-use password reset token (15m TTL) | `3/min` | No |
| **POST** | `/reset` | Consumes reset token and updates password | `5/min` | No |
| **GET** | `/admin/users` | Lists all users (RBAC protected) | Default | Admin JWT |
| **POST** | `/admin/unlock/{id}` | Unlocks a locked account | Default | Admin JWT |

---

## 🛡️ Security & Compliance Standards

1. **Password Policy:** Minimum 8 characters with required uppercase, lowercase, numerical digit, and special character.
2. **RFC 6749 Section 10.4 Compliant:** Enforces refresh token rotation and token reuse detection.
3. **Session Revocation:** JWT access tokens blacklisted upon logout; refresh tokens explicitly invalidated in database.
4. **Resilient Architecture:** Zero unhandled crashes on DNS or network drops; returns standardized HTTP 503 and 429 status codes.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
