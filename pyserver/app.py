import os
import json
import logging
import sqlite3
from pathlib import Path
from typing import Dict, Any
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from base64 import urlsafe_b64encode, urlsafe_b64decode
from secrets import token_bytes
import time
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

from webauthn import (
    verify_registration_response,
    verify_authentication_response,
)

# Load environment variables from .env file
load_dotenv()

# --------------------------------------------------------------------------------------
# Paths and setup
# --------------------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "log"
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("DATABASE_PATH", DATA_DIR / "app.db"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
PID_FILE = BASE_DIR / "server.pid"

# Logging setup: console + file
logger = logging.getLogger("pyserver")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(console_handler)

file_handler = logging.FileHandler(LOG_DIR / "server.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(file_handler)

# API access logger (per-request)
api_logger = logging.getLogger("pyserver.api")
api_logger.setLevel(logging.INFO)
api_console = logging.StreamHandler()
api_console.setLevel(logging.INFO)
api_console.setFormatter(logging.Formatter("[API] %(message)s"))
api_logger.addHandler(api_console)
api_file = logging.FileHandler(LOG_DIR / "api.log")
api_file.setLevel(logging.INFO)
api_file.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
api_logger.addHandler(api_file)

# Error logger
error_logger = logging.getLogger("pyserver.error")
error_logger.setLevel(logging.ERROR)
err_console = logging.StreamHandler()
err_console.setLevel(logging.ERROR)
err_console.setFormatter(logging.Formatter("[ERROR] %(message)s"))
error_logger.addHandler(err_console)
err_file = logging.FileHandler(LOG_DIR / "error.log")
err_file.setLevel(logging.ERROR)
err_file.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
error_logger.addHandler(err_file)

# --------------------------------------------------------------------------------------
# Flask app
# --------------------------------------------------------------------------------------
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)

# RP info
RP_NAME = "Fingerprint 2FA App"
RP_ID = "localhost"  # domain part only
EXPECTED_ORIGIN = "http://localhost:3000"

# Email configuration from environment variables
EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER", "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "587"))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME", "your-email@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "your-app-password")
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "SecureAuth")

# In-memory challenges per username
username_to_challenge: Dict[str, str] = {}

# Backup tokens list
BACKUP_TOKENS = [
    "cat", "dog", "bird", "fish", "lion", "tiger", "bear", "wolf", "fox", "deer",
    "mango", "apple", "banana", "orange", "grape", "cherry", "lemon", "lime", "peach", "pear",
    "giraffe", "elephant", "zebra", "hippo", "rhino", "panda", "koala", "kangaroo", "monkey", "penguin",
    "ocean", "mountain", "forest", "desert", "river", "lake", "valley", "canyon", "island", "beach",
    "sunset", "rainbow", "thunder", "lightning", "snowflake", "raindrop", "cloud", "star", "moon", "sun"
]

# --------------------------------------------------------------------------------------
# SQLite helpers
# --------------------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY,
              user_id  BLOB NOT NULL,
              allowed_devices TEXT NOT NULL DEFAULT '[]',
              fingerprint_hash TEXT,
              backup_token TEXT
            )
            """
        )
        # Add backup_token column to existing users table if it doesn't exist
        try:
            conn.execute("ALTER TABLE users ADD COLUMN backup_token TEXT")
        except sqlite3.OperationalError:
            # Column already exists, ignore the error
            pass
        
        # Generate backup tokens for existing users who don't have one
        users_without_tokens = conn.execute(
            "SELECT username FROM users WHERE backup_token IS NULL OR backup_token = ''"
        ).fetchall()
        
        for user in users_without_tokens:
            token = generate_backup_token()
            conn.execute(
                "UPDATE users SET backup_token = ? WHERE username = ?",
                (token, user["username"])
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              credential_id BLOB NOT NULL,
              credential_public_key BLOB NOT NULL,
              sign_count INTEGER NOT NULL,
              transports TEXT,
              FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
    conn.close()
    logger.info(f"[DB] Initialized at {DB_PATH}")


def get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT username, user_id, allowed_devices, fingerprint_hash, backup_token FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def insert_user(conn: sqlite3.Connection, username: str, user_id: bytes) -> None:
    backup_token = generate_backup_token()
    conn.execute(
        "INSERT INTO users (username, user_id, allowed_devices, backup_token) VALUES (?, ?, '[]', ?)",
        (username, user_id, backup_token),
    )


def get_credentials(conn: sqlite3.Connection, username: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, credential_id, credential_public_key, sign_count, transports FROM credentials WHERE username = ?",
        (username,),
    ).fetchall()


def get_credential_by_id(conn: sqlite3.Connection, credential_id: bytes) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, credential_id, credential_public_key, sign_count, transports FROM credentials WHERE credential_id = ?",
        (credential_id,),
    ).fetchone()


def get_user_by_user_id(conn: sqlite3.Connection, user_id: bytes) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT username, user_id, allowed_devices, fingerprint_hash, backup_token FROM users WHERE user_id = ?",
        (user_id,),
    ).fetchone()


def insert_credential(
    conn: sqlite3.Connection,
    username: str,
    credential_id: bytes,
    credential_public_key: bytes,
    sign_count: int,
    transports_json: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO credentials (username, credential_id, credential_public_key, sign_count, transports)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, credential_id, credential_public_key, sign_count, transports_json),
    )


def update_allowed_devices(conn: sqlite3.Connection, username: str, devices: list[str]) -> None:
    conn.execute(
        "UPDATE users SET allowed_devices = ? WHERE username = ?",
        (json.dumps(devices), username),
    )


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return urlsafe_b64decode(s + padding)


def generate_backup_token() -> str:
    """Generate a random backup token with 7 random words from the predefined list"""
    return " ".join(random.choices(BACKUP_TOKENS, k=7))


@app.before_request
def log_request_body():
    g._start = time.perf_counter()
    try:
        body = request.get_json(silent=True)
    except Exception:
        body = None
    logger.info(f"[REQ] {request.method} {request.path} body={body}")


@app.after_request
def access_log(response):
    duration_ms = (time.perf_counter() - getattr(g, "_start", time.perf_counter())) * 1000.0
    length = response.calculate_content_length()
    api_logger.info(f"{request.remote_addr or '-'} {request.method} {request.path} {response.status_code} {length} {duration_ms:.1f}ms")
    return response


@app.errorhandler(Exception)
def handle_exception(exc):
    error_logger.exception("Unhandled exception during request")
    return jsonify({"message": str(exc)}), 500


@app.get("/health")
def health():
    return {"ok": True}


# --------------------------------------------------------------------------------------
# WebAuthn - Registration
# --------------------------------------------------------------------------------------
@app.post("/register-webauthn")
def register_webauthn():
    payload: Dict[str, Any] = request.get_json(force=True)
    username: str = (payload.get("username") or "").strip()
    if not username:
        return jsonify({"message": "Missing username"}), 400

    conn = get_db()
    try:
        with conn:
            row = get_user(conn, username)
            if row is None:
                user_id = token_bytes(16)
                insert_user(conn, username, user_id)
                row = get_user(conn, username)
            else:
                creds = get_credentials(conn, username)
                if len(creds) > 0:
                    return jsonify({"message": "User already exists"}), 400

        assert row is not None
        user_id_bytes: bytes = row["user_id"]

        # Manually build PublicKeyCredentialCreationOptions
        challenge_bytes = token_bytes(32)
        options = {
            "rp": {"name": RP_NAME, "id": RP_ID},
            "user": {
                "id": b64url_encode(user_id_bytes),
                "name": username,
                "displayName": username,
            },
            "challenge": b64url_encode(challenge_bytes),
            "pubKeyCredParams": [
                {"alg": -7, "type": "public-key"},
                {"alg": -257, "type": "public-key"},
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "userVerification": "required",
                "residentKey": "preferred",
            },
        }
        username_to_challenge[username] = options["challenge"]
        logger.info(f"[REGISTER] challenge={options['challenge']}")
        return jsonify(options)
    except Exception as exc:
        logger.exception("[REGISTER] options error")
        return jsonify({"message": str(exc)}), 500
    finally:
        conn.close()


@app.post("/verify-registration")
def verify_registration():
    payload: Dict[str, Any] = request.get_json(force=True)
    username = (payload.get("username") or "").strip()
    response = payload.get("response")

    if not username or not response:
        return jsonify({"message": "Missing fields"}), 400

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None:
            return jsonify({"message": "User not found"}), 404

        expected_challenge_str = username_to_challenge.get(username)
        if not expected_challenge_str:
            return jsonify({"message": "No pending challenge"}), 400

        expected_challenge = b64url_decode(expected_challenge_str)
        logger.info(f"[VERIFY REGISTER] expected_challenge(b64)={expected_challenge_str}")

        verification = verify_registration_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
        )
        # No exception == success. Extract fields defensively.
        cred_id = getattr(verification, "credential_id", None) or (
            verification.get("credential_id") if isinstance(verification, dict) else None
        )
        cred_pub = getattr(verification, "credential_public_key", None) or (
            verification.get("credential_public_key") if isinstance(verification, dict) else None
        )
        sign_count = getattr(verification, "sign_count", None) or (
            verification.get("sign_count") if isinstance(verification, dict) else 0
        )
        transports = getattr(verification, "transports", None) or (
            verification.get("transports") if isinstance(verification, dict) else None
        )
        if cred_id is None or cred_pub is None:
            return jsonify({"message": "Registration failed: missing credential data"}), 400

        transports_json = json.dumps(list(transports)) if transports else None
        with conn:
            insert_credential(
                conn,
                username,
                cred_id,
                cred_pub,
                int(sign_count or 0),
                transports_json,
            )
        username_to_challenge.pop(username, None)
        
        # Get the generated backup token
        user_row = get_user(conn, username)
        backup_token = user_row["backup_token"] if user_row else None
        
        return jsonify({
            "message": "Registration successful", 
            "backup_token": backup_token
        })
    except Exception as exc:
        logger.exception("[VERIFY REGISTER] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


# --------------------------------------------------------------------------------------
# WebAuthn - Authentication
# --------------------------------------------------------------------------------------
@app.post("/login-webauthn")
def login_webauthn():
    payload: Dict[str, Any] = request.get_json(force=True)
    username = (payload.get("username") or "").strip()
    if not username:
        return jsonify({"message": "Missing username"}), 400

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None:
            return jsonify({"message": "User not found"}), 404
        creds = get_credentials(conn, username)
        if len(creds) == 0:
            return jsonify({"message": "No credentials registered"}), 400

        # Manually build PublicKeyCredentialRequestOptions
        challenge_bytes = token_bytes(32)
        allow_list = []
        for c in creds:
            d = {
                "id": b64url_encode(c["credential_id"]),
                "type": "public-key",
            }
            tr = json.loads(c["transports"]) if c["transports"] else None
            if tr:
                d["transports"] = tr
            allow_list.append(d)

        options = {
            "rpId": RP_ID,
            "challenge": b64url_encode(challenge_bytes),
            "allowCredentials": allow_list,
            "userVerification": "required",
            "timeout": 60000,
        }
        username_to_challenge[username] = options["challenge"]
        logger.info(f"[LOGIN] challenge={options['challenge']}")
        return jsonify(options)
    except Exception as exc:
        logger.exception("[LOGIN] options error")
        return jsonify({"message": str(exc)}), 500
    finally:
        conn.close()


@app.post("/verify-authentication")
def verify_authentication():
    payload: Dict[str, Any] = request.get_json(force=True)
    username = (payload.get("username") or "").strip()
    response = payload.get("response")
    device_id = (payload.get("deviceId") or "device123").strip()

    if not username or not response:
        return jsonify({"message": "Missing fields"}), 400

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None:
            return jsonify({"message": "User not found"}), 404

        expected_challenge_str = username_to_challenge.get(username)
        if not expected_challenge_str:
            return jsonify({"message": "No pending challenge"}), 400
        expected_challenge = b64url_decode(expected_challenge_str)

        creds = get_credentials(conn, username)
        if len(creds) == 0:
            return jsonify({"message": "No credentials registered"}), 400

        _verification = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            credential_public_key=creds[0]["credential_public_key"],
            credential_current_sign_count=creds[0]["sign_count"],
        )
        # If no exception, consider verified

        # Update device list
        allowed_devices = json.loads(row["allowed_devices"]) if row["allowed_devices"] else []
        if device_id not in allowed_devices:
            allowed_devices.append(device_id)
            with conn:
                update_allowed_devices(conn, username, allowed_devices)
        username_to_challenge.pop(username, None)
        return jsonify({"message": "Login successful"})
    except Exception as exc:
        logger.exception("[VERIFY LOGIN] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


# --------------------------------------------------------------------------------------
# WebAuthn - Authentication (discovery, no username)
# --------------------------------------------------------------------------------------
@app.post("/login-webauthn-any")
def login_webauthn_any():
    # Build options without allowCredentials so the platform can select the account
    try:
        challenge_bytes = token_bytes(32)
        options = {
            "rpId": RP_ID,
            "challenge": b64url_encode(challenge_bytes),
            "allowCredentials": [],  # empty array enables account discovery
            "userVerification": "required",
            "timeout": 60000,
        }
        # Use a special key for tracking challenge without username
        username_to_challenge["__any__"] = options["challenge"]
        logger.info(f"[LOGIN ANY] challenge={options['challenge']}")
        return jsonify(options)
    except Exception as exc:
        logger.exception("[LOGIN ANY] options error")
        return jsonify({"message": str(exc)}), 500


@app.post("/verify-authentication-any")
def verify_authentication_any():
    payload: Dict[str, Any] = request.get_json(force=True)
    response = payload.get("response")
    device_id = (payload.get("deviceId") or "device123").strip()

    if not response:
        return jsonify({"message": "Missing response"}), 400

    # Resolve expected challenge
    expected_challenge_str = username_to_challenge.get("__any__")
    if not expected_challenge_str:
        return jsonify({"message": "No pending challenge"}), 400
    expected_challenge = b64url_decode(expected_challenge_str)

    # Extract credential id (primary) and optional userHandle
    cred_id_b64 = payload.get("id") or response.get("id")
    if not cred_id_b64:
        return jsonify({"message": "Missing credential id"}), 400
    cred_id = b64url_decode(cred_id_b64)
    user_handle_b64 = response.get("response", {}).get("userHandle")

    conn = get_db()
    try:
        # Resolve credential first
        cred_row = get_credential_by_id(conn, cred_id)
        if cred_row is None:
            return jsonify({"message": "Credential not recognized"}), 404
        username = cred_row["username"]
        # Load user by username
        user_row = get_user(conn, username)
        if user_row is None:
            return jsonify({"message": "User not found for this credential"}), 404

        _verification = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            credential_public_key=cred_row["credential_public_key"],
            credential_current_sign_count=cred_row["sign_count"],
        )

        # Update device list for the resolved user
        allowed_devices = json.loads(user_row["allowed_devices"]) if user_row["allowed_devices"] else []
        if device_id not in allowed_devices:
            allowed_devices.append(device_id)
            with conn:
                update_allowed_devices(conn, username, allowed_devices)
        username_to_challenge.pop("__any__", None)
        return jsonify({"message": f"Login successful as {username}", "username": username})
    except Exception as exc:
        logger.exception("[VERIFY LOGIN ANY] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


# --------------------------------------------------------------------------------------
# Token-based Authentication (Backup)
# --------------------------------------------------------------------------------------
@app.post("/login-token")
def login_with_token():
    payload: Dict[str, Any] = request.get_json(force=True)
    username = (payload.get("username") or "").strip()
    token = (payload.get("token") or "").strip()
    device_id = (payload.get("deviceId") or "device123").strip()

    if not username or not token:
        return jsonify({"message": "Missing username or token"}), 400

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None:
            return jsonify({"message": "User not found"}), 404

        stored_token = row["backup_token"]
        if not stored_token or token.lower().strip() != stored_token.lower().strip():
            return jsonify({"message": "Invalid token"}), 401

        # Update device list
        allowed_devices = json.loads(row["allowed_devices"]) if row["allowed_devices"] else []
        if device_id not in allowed_devices:
            allowed_devices.append(device_id)
            with conn:
                update_allowed_devices(conn, username, allowed_devices)

        logger.info(f"[TOKEN LOGIN] successful for {username}")
        return jsonify({"message": "Token login successful"})
    except Exception as exc:
        logger.exception("[TOKEN LOGIN] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


@app.get("/get-backup-token/<username>")
def get_backup_token(username: str):
    """Get the backup token for a user (for display purposes)"""
    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None:
            return jsonify({"message": "User not found"}), 404

        token = row["backup_token"]
        if not token:
            return jsonify({"message": "No backup token found"}), 404

        return jsonify({"token": token})
    except Exception as exc:
        logger.exception("[GET TOKEN] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


@app.post("/regenerate-backup-token")
def regenerate_backup_token():
    """Regenerate backup token for a user"""
    payload: Dict[str, Any] = request.get_json(force=True)
    username = (payload.get("username") or "").strip()

    if not username:
        return jsonify({"message": "Missing username"}), 400

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None:
            return jsonify({"message": "User not found"}), 404

        # Generate new 7-word token
        new_token = generate_backup_token()
        
        with conn:
            conn.execute(
                "UPDATE users SET backup_token = ? WHERE username = ?",
                (new_token, username)
            )

        logger.info(f"[REGENERATE TOKEN] new token generated for {username}")
        return jsonify({"message": "Token regenerated successfully", "token": new_token})
    except Exception as exc:
        logger.exception("[REGENERATE TOKEN] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send email using SMTP"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"{EMAIL_FROM_NAME} <{EMAIL_USERNAME}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'plain'))
        
        # Create SMTP session
        server = smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT)
        server.starttls()  # Enable security
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        
        # Send email
        text = msg.as_string()
        server.sendmail(EMAIL_USERNAME, to_email, text)
        server.quit()
        
        logger.info(f"[EMAIL] Successfully sent email to {to_email}")
        return True
    except Exception as exc:
        logger.exception(f"[EMAIL] Failed to send email to {to_email}")
        return False


@app.post("/forgot-token")
def forgot_token():
    """Send backup token to user's email"""
    payload: Dict[str, Any] = request.get_json(force=True)
    email = (payload.get("email") or "").strip()

    if not email:
        return jsonify({"message": "Email is required"}), 400

    conn = get_db()
    try:
        row = get_user(conn, email)
        if row is None:
            return jsonify({"message": "User not found"}), 404

        backup_token = row["backup_token"]
        if not backup_token:
            return jsonify({"message": "No backup token found for this user"}), 404

        # Send email with backup token
        subject = "Your SecureAuth Backup Token"
        body = f"""
Hello,

You requested your backup token for SecureAuth.

Your backup token is: {backup_token}

This token contains 7 random words for enhanced security.

Important Security Notes:
- Keep this token safe and don't share it with anyone
- You can use this token to login if your fingerprint doesn't work
- If you didn't request this token, please contact support immediately

Best regards,
SecureAuth Team
        """.strip()

        if send_email(email, subject, body):
            logger.info(f"[FORGOT TOKEN] Token sent to {email}")
            return jsonify({"message": "Backup token sent to your email"})
        else:
            return jsonify({"message": "Failed to send email. Please try again later."}), 500

    except Exception as exc:
        logger.exception("[FORGOT TOKEN] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    # Write PID for external control scripts
    try:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass
    
    # Server configuration from environment variables
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    
    logger.info(f"Python WebAuthn server running at http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=DEBUG)
