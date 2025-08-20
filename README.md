# Fingerprint Passkey (Cross‑Device 2FA Demo)

A practical demo of a fingerprint/passkey-based, OTP‑free 2FA model. It provides:

- React web client with a dedicated fingerprint test page
- Two backend choices:
  - Python (Flask) WebAuthn server with SQLite and structured logs
  - Node.js (Express) WebAuthn server with SQLite and structured logs
- Optional React Native app (Android/iOS) to mirror the same flows

The goal is to authenticate with a single fingerprint prompt. The demo supports classic username-based flows and passkey “account discovery” (no username) on the fingerprint test page.

## Repository layout

- `web-client/` React web app (Create React App)
- `pyserver/` Python (Flask) WebAuthn server
  - `setup_and_run_windows.bat`: menu to install deps and start server (logs in same window)
  - `setup_and_run_mac.sh`: macOS/Linux setup + run
  - `log/`: server logs (`server.log`, `api.log`, `error.log`)
  - `data/app.db`: SQLite database
- `server/` Node.js (Express) server (alternative backend)
  - `log/server.log`: request logs
  - `data/app.db` (if enabled): SQLite database
- `FingerprintApp/` React Native client (optional)

## Features

- WebAuthn/Passkeys (platform authenticator / Windows Hello)
- Registration (creates a resident passkey)
- Authentication (username flow)
- Account discovery login (no username) on `/fingerprinttest`
- Device list simulation (adds a device on first login)
- Structured logging + SQLite persistence (Python server)

## Prerequisites

- Node.js 18+ and npm
- Python 3.10+
- A modern browser supporting WebAuthn (Chrome/Edge)
- Windows Hello fingerprint enrolled (for platform authenticator testing)

## Quick start (recommended: Python backend)

1) Start the Python server (Windows)

- Open a terminal in `pyserver/` and run:

```
setup_and_run_windows.bat
```

- Choose option `2` once to Install/Update requirements
- Choose option `1` to Start server
- Server runs at `http://localhost:5000`

2) Start the web client

```
cd web-client
npm install
npm start
```

The CRA dev server runs at `http://localhost:3000` and proxies API to `http://localhost:5000` (already configured in `web-client/package.json`).

3) Test the flows

- Visit `http://localhost:3000/`
  - Register: enter a username and complete the fingerprint prompt
  - Login: enter the same username and complete the fingerprint prompt
- Visit `http://localhost:3000/fingerprinttest`
  - Click `Register` once with a username to create a resident passkey
  - Click `Fingerprint` (no username) → it pops the fingerprint UI and shows the detected username. If none is found, you’ll see “No user with this fingerprint”.

## Alternative: Node.js backend

If you prefer Node.js instead of Python:

```
cd server
npm install
npm start
```

Then update the CRA proxy to port 5000 or 3000 accordingly in `web-client/package.json`, and restart `npm start` in `web-client`.

Note: The Python backend is the recommended path in this repo and is what the fingerprint test page targets by default.

## Logs & data

- Python server (preferred):
  - Logs: `pyserver/log/`
    - `server.log`: general/info, request bodies
    - `api.log`: one-line access entries with status and timing
    - `error.log`: stack traces
  - Database: `pyserver/data/app.db` (SQLite)

- Node server:
  - Logs: `server/log/server.log`
  - Database (if enabled): `server/data/app.db` (SQLite)

## Troubleshooting

- No fingerprint prompt
  - Ensure Windows Hello has a fingerprint enrolled (Windows Settings → Accounts → Sign‑in options)
  - Use Chrome/Edge (recent versions)
  - Confirm the server is running on `:5000` and the CRA proxy is set to `http://localhost:5000`

- CORS / Failed to fetch
  - Make sure the server is running before the web app
  - With CRA, requests are proxied via `web-client/package.json` → restart `npm start` after changes

- Account discovery returns 404
  - You must register at least once on this server so a resident key exists in `app.db`.

- Development HTTPS
  - WebAuthn works on `http://localhost` for development. For non-localhost you must use HTTPS.

## React Native (optional)

- The React Native app (`FingerprintApp/`) mirrors the basic flows. For Android emulators, the server base URL is typically `http://10.0.2.2:5000`.

## Security notes

This is a demo:
- The Python and Node servers are development servers; do not deploy as-is.
- Keys and credentials are stored locally in SQLite for demo purposes.
- In production, use a hardened WebAuthn library/server (and HTTPS), implement liveness detection where applicable, and add rate-limiting and anomaly detection.

## License

MIT (or your preferred license).
