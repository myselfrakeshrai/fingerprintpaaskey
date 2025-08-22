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
from werkzeug.security import generate_password_hash, check_password_hash

from webauthn import (
    verify_registration_response,
    verify_authentication_response,
)

# --------------------------------------------------------------------------------------
# Paths and setup
# --------------------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "log"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "app.db"
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

# In-memory challenges per username
username_to_challenge: Dict[str, str] = {}

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
              fingerprint_hash TEXT
            )
            """
        )
        # Add new columns if they don't exist yet
        try:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        except sqlite3.OperationalError:
            pass
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
        "SELECT username, user_id, allowed_devices, fingerprint_hash, email, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def insert_user(conn: sqlite3.Connection, username: str, user_id: bytes) -> None:
    conn.execute(
        "INSERT INTO users (username, user_id, allowed_devices) VALUES (?, ?, '[]')",
        (username, user_id),
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
        "SELECT username, user_id, allowed_devices, fingerprint_hash FROM users WHERE user_id = ?",
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


def ensure_auth_columns(conn: sqlite3.Connection) -> None:
    """Ensure optional auth columns exist even if init_db didn't run this boot."""
    try:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except sqlite3.OperationalError:
        pass


def set_user_auth_fields(
    conn: sqlite3.Connection,
    username: str,
    *,
    email: str | None = None,
    password_hash: str | None = None,
    fingerprint_hash: str | None = None,
) -> None:
    # Build dynamic update based on provided fields
    fields: list[str] = []
    values: list[object] = []
    if email is not None:
        fields.append("email = ?")
        values.append(email)
    if password_hash is not None:
        fields.append("password_hash = ?")
        values.append(password_hash)
    if fingerprint_hash is not None:
        fields.append("fingerprint_hash = ?")
        values.append(fingerprint_hash)
    if not fields:
        return
    values.append(username)
    sql = f"UPDATE users SET {', '.join(fields)} WHERE username = ?"
    conn.execute(sql, tuple(values))


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return urlsafe_b64decode(s + padding)


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
        return jsonify({"message": "Registration successful"})
    except Exception as exc:
        logger.exception("[VERIFY REGISTER] error")
        return jsonify({"message": str(exc)}), 400
    finally:
        conn.close()


# --------------------------------------------------------------------------------------
# Password + Fingerprint 2FA endpoints
# --------------------------------------------------------------------------------------

# In-memory short-lived tokens created after password verification
password_ok_tokens: dict[str, dict[str, object]] = {}


@app.post("/register-password")
def register_password():
    payload: Dict[str, Any] = request.get_json(force=True)
    username: str = (payload.get("username") or "").strip()
    email: str = (payload.get("email") or "").strip()
    password: str = (payload.get("password") or "").strip()
    fingerprint: str = (payload.get("fingerprint") or "").strip()
    fingerprint_hash_from_device: str = (payload.get("fingerprintHash") or "").strip()

    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    conn = get_db()
    try:
        with conn:
            ensure_auth_columns(conn)
            row = get_user(conn, username)
            if row is None:
                user_id = token_bytes(16)
                insert_user(conn, username, user_id)
                row = get_user(conn, username)
            # Do not overwrite existing credentials
            if row.get("password_hash") if isinstance(row, dict) else row["password_hash"]:
                return jsonify({"message": "User already registered with password"}), 400

            pwd_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
            # If a device-provided fingerprint hash is present, we hash THAT value for storage.
            # Otherwise, if a raw fingerprint string is present, we hash that.
            fp_source = fingerprint_hash_from_device or fingerprint or None
            fp_hash = (
                generate_password_hash(fp_source, method="pbkdf2:sha256", salt_length=16)
                if fp_source
                else None
            )
            set_user_auth_fields(
                conn,
                username,
                email=email,
                password_hash=pwd_hash,
                fingerprint_hash=fp_hash,
            )
        return jsonify({"message": "Registration successful"})
    except Exception as exc:
        logger.exception("[REGISTER PASSWORD] error")
        return jsonify({"message": str(exc)}), 500
    finally:
        conn.close()


@app.post("/login-password")
def login_password():
    payload: Dict[str, Any] = request.get_json(force=True)
    username: str = (payload.get("username") or "").strip()
    password: str = (payload.get("password") or "").strip()

    if not username or not password:
        return jsonify({"message": "Missing fields"}), 400

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None or not (row.get("password_hash") if isinstance(row, dict) else row["password_hash"]):
            return jsonify({"message": "Invalid username or password"}), 401
        if not check_password_hash(row.get("password_hash") if isinstance(row, dict) else row["password_hash"], password):
            return jsonify({"message": "Invalid username or password"}), 401

        token = b64url_encode(token_bytes(24))
        password_ok_tokens[username] = {"token": token, "exp": time.time() + 300.0}
        return jsonify({"message": "Password OK", "passwordToken": token})
    except Exception as exc:
        logger.exception("[LOGIN PASSWORD] error")
        return jsonify({"message": str(exc)}), 500
    finally:
        conn.close()


@app.post("/verify-fingerprint")
def verify_fingerprint():
    payload: Dict[str, Any] = request.get_json(force=True)
    username: str = (payload.get("username") or "").strip()
    fingerprint: str = (payload.get("fingerprint") or "").strip()
    fingerprint_hash_from_device: str = (payload.get("fingerprintHash") or "").strip()
    device_id: str = (payload.get("deviceId") or "device123").strip()
    token: str = (payload.get("passwordToken") or "").strip()

    if not username or not token:
        return jsonify({"message": "Missing fields"}), 400

    # Validate short-lived password token
    entry = password_ok_tokens.get(username)
    if not entry or entry.get("token") != token or float(entry.get("exp", 0)) < time.time():
        return jsonify({"message": "Password verification required"}), 401

    conn = get_db()
    try:
        row = get_user(conn, username)
        if row is None or not row["fingerprint_hash"]:
            return jsonify({"message": "Fingerprint not enrolled"}), 400
        # Candidate to verify: prefer device-provided hash, fallback to raw fingerprint string
        candidate = fingerprint_hash_from_device or fingerprint
        if not candidate:
            return jsonify({"message": "Missing fingerprint"}), 400
        if not check_password_hash(row["fingerprint_hash"], candidate):
            return jsonify({"message": "Fingerprint mismatch"}), 401

        # Update allowed devices
        allowed_devices = json.loads(row["allowed_devices"]) if row["allowed_devices"] else []
        if device_id not in allowed_devices:
            allowed_devices.append(device_id)
            with conn:
                update_allowed_devices(conn, username, allowed_devices)

        # Invalidate token after successful 2FA
        password_ok_tokens.pop(username, None)
        return jsonify({"message": "2FA successful"})
    except Exception as exc:
        logger.exception("[VERIFY FINGERPRINT] error")
        return jsonify({"message": str(exc)}), 500
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

        authenticator = {
            "credential_id": creds[0]["credential_id"],
            "credential_public_key": creds[0]["credential_public_key"],
            "sign_count": creds[0]["sign_count"],
            "transports": json.loads(creds[0]["transports"]) if creds[0]["transports"] else None,
        }

        _verification = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            authenticator=authenticator,
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

        authenticator = {
            "credential_id": cred_row["credential_id"],
            "credential_public_key": cred_row["credential_public_key"],
            "sign_count": cred_row["sign_count"],
            "transports": json.loads(cred_row["transports"]) if cred_row["transports"] else None,
        }

        _verification = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            authenticator=authenticator,
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


if __name__ == "__main__":
    init_db()
    # Write PID for external control scripts
    try:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass
    logger.info("Python WebAuthn server running at http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
