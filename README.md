# AuthShield

AuthShield is a secure, production-ready user authentication and authorization API built with **FastAPI** and **MongoDB**. It implements industry-standard security protocols, including JWT access and refresh tokens, password hashing, automated account lockouts, password resets, and role-based access control.

---

## 🚀 Features

- **User Registration (`/signup`)**:
  - Email format validation.
  - Password complexity validation (minimum 8 characters).
  - Secure password hashing using `bcrypt` (via `passlib`).
- **User Authentication (`/login`)**:
  - Verification of hashed passwords.
  - Generation of short-lived JWT **access tokens** (15-minute expiry).
  - Generation of secure UUID-based **refresh tokens** stored in MongoDB.
- **Account Lockout Protection**:
  - Track failed login attempts.
  - Automatically locks accounts after **3 consecutive failed attempts** to prevent brute-force attacks.
- **Token Lifecycle Management**:
  - **Token Refresh (`/refresh`)**: Obtain a new access token using a valid refresh token.
  - **Session Logout (`/logout`)**: Blacklists active JWT access tokens in MongoDB to invalidate them immediately.
- **Protected Routes**:
  - **Profile (`/profile`)**: Fetches details of the currently authenticated user.
  - **Admin User List (`/admin/users`)**: Restricted role-based endpoint allowing only users with the `admin` role to list all users.
- **Password Recovery & Reset (`/forgot`, `/reset`)**:
  - Generates secure, single-use password reset tokens.
  - Securely updates the password and invalidates the reset token after use.

---

## 📁 Project Structure

```text
authproject/
│
├── main.py          # FastAPI application initialization & API route handlers
├── auth.py          # Security utilities (hashing, JWT encoding, verification)
├── database.py      # MongoDB client connection and collection references
├── schemas.py       # Pydantic data schemas for request and response validation
├── models.py        # SQLAlchemy models (for SQL database compatibility)
├── requirements.txt # Python package dependencies
└── README.md        # Project documentation
```

---

## 🛠️ Setup & Installation

### 1. Prerequisites
- Python 3.8 or higher.
- A running MongoDB instance (or a MongoDB Atlas connection string).

### 2. Installation
Clone this repository (or navigate to the project directory) and set up a virtual environment:

```bash
# Navigate to the project folder
cd authproject

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install the required dependencies
pip install -r requirements.txt
```

### 3. Database Configuration
By default, the connection URL is configured in `database.py`. It is recommended to use environment variables in production:
```python
# database.py
MONGO_URL = "your_mongodb_connection_string"
```

### 4. Running the Application
Start the FastAPI development server using `uvicorn`:

```bash
uvicorn main:app --reload
```

The API will be available at your local host.

---

## 📖 API Endpoints

Once the application is running, you can access the interactive Swagger documentation at url of the local host.

### Summary of Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| **POST** | `/signup` | Register a new user | No |
| **POST** | `/login` | Log in and receive access/refresh tokens | No |
| **POST** | `/refresh` | Get a new access token using a refresh token | No |
| **POST** | `/logout` | Log out and blacklist the current access token | Yes |
| **GET** | `/profile` | Retrieve the authenticated user's profile | Yes |
| **POST** | `/forgot` | Request a password reset token | No |
| **POST** | `/reset` | Reset password using a valid token | No |
| **GET** | `/admin/users` | List all users (Admins only) | Yes (Admin) |

---

## 🔒 Security Best Practices Implemented

1. **Password Hashing**: Never stores raw passwords; instead uses `bcrypt` to hash passwords.
2. **Access Token Expiry**: Access tokens are short-lived (15 minutes) to minimize the impact of leaked tokens.
3. **Token Blacklisting**: Logout immediately invalidates the access token by adding it to a database blacklist.
4. **Brute-Force Lockout**: Limits account access after 3 failed login attempts.
