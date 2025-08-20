const express = require('express'); 
const bodyParser = require('body-parser'); 
const crypto = require('crypto'); 
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const sqlite3 = require('sqlite3').verbose();
const app = express(); 
const port = 5000; 
const cors = require('cors');
  
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// Ensure directories exist INSIDE server folder
const logDir = path.join(__dirname, 'log');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const accessLogStream = fs.createWriteStream(path.join(logDir, 'server.log'), { flags: 'a' });

// Initialize SQLite database
const dbPath = path.join(dataDir, 'app.db');
const db = new sqlite3.Database(dbPath);

// Promisified helpers
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// Create tables
(async () => {
  await dbRun(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    userId BLOB NOT NULL,
    fingerprintHash TEXT,
    allowedDevices TEXT NOT NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    credentialID BLOB NOT NULL,
    credentialPublicKey BLOB NOT NULL,
    counter INTEGER NOT NULL,
    transports TEXT,
    FOREIGN KEY(username) REFERENCES users(username)
  )`);
  console.log(`[DB] Initialized at ${dbPath}`);
})().catch(err => {
  console.error('[DB] Initialization error:', err);
  process.exit(1);
});

// In-memory challenges per user
const challenges = new Map();

// Human-readable title for your website
const rpName = 'Fingerprint 2FA App';
// A unique identifier for your website
const rpID = 'localhost';

// Middleware 
app.use(bodyParser.json()); 

// Logging: console and file
app.use(morgan('dev'));
app.use(morgan('combined', { stream: accessLogStream }));

// Use CORS middleware (reflect request origin)
app.use(cors({
  origin: true,
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  optionsSuccessStatus: 200,
}));

// Debug log for each request body
app.use((req, res, next) => {
  console.log(`[DEBUG] ${req.method} ${req.originalUrl} body=`, req.body);
  next();
});

// Mock biometric hashing (simulates SHA-256) 
function hashFingerprint(fingerprint) { 
  return crypto.createHash('sha256').update(fingerprint).digest('hex'); 
} 

// Helper: fetch user
async function getUser(username) {
  return dbGet('SELECT username, userId, fingerprintHash, allowedDevices FROM users WHERE username = ?', [username]);
}

// Helper: insert user
async function insertUser({ username, userId, fingerprintHash = null, allowedDevices = [] }) {
  const allowed = JSON.stringify(allowedDevices);
  await dbRun('INSERT INTO users (username, userId, fingerprintHash, allowedDevices) VALUES (?, ?, ?, ?)', [username, userId, fingerprintHash, allowed]);
}

// Helper: update allowed devices
async function updateAllowedDevices(username, allowedDevices) {
  const allowed = JSON.stringify(allowedDevices);
  await dbRun('UPDATE users SET allowedDevices = ? WHERE username = ?', [allowed, username]);
}

// Helper: load credentials for user
async function getCredentials(username) {
  return dbAll('SELECT id, credentialID, credentialPublicKey, counter, transports FROM credentials WHERE username = ?', [username]);
}

// Helper: insert credential
async function insertCredential(username, info) {
  const transports = info.transports ? JSON.stringify(info.transports) : null;
  await dbRun(
    'INSERT INTO credentials (username, credentialID, credentialPublicKey, counter, transports) VALUES (?, ?, ?, ?, ?)',
    [username, info.credentialID, info.credentialPublicKey, info.counter, transports]
  );
}

// Register endpoint (mock path kept for reference)
app.post('/register', async (req, res) => { 
  const { username, fingerprint, deviceId } = req.body; 
  console.log('[REGISTER] payload:', { username, deviceId });

  if (!username || !fingerprint || !deviceId) { 
    return res.status(400).json({ message: 'Missing required fields' }); 
  } 

  try {
    const existing = await getUser(username);
    if (existing) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const userId = crypto.randomBytes(16);
    await insertUser({
      username,
      userId,
      fingerprintHash: hashFingerprint(fingerprint),
      allowedDevices: [deviceId],
    });

    res.json({ message: 'Registration successful' });
  } catch (err) {
    console.error('[REGISTER] error:', err);
    res.status(500).json({ message: 'Server error' });
  }
}); 

// Helper: base64url encode Buffer
function toBase64URL(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

// Register endpoint for WebAuthn
app.post('/register-webauthn', async (req, res) => {
  const { username } = req.body;
  console.log('[WEBAUTHN REGISTER] username:', username);

  if (!username) {
    return res.status(400).json({ message: 'Missing username' });
  }

  try {
    let user = await getUser(username);
    if (!user) {
      const userId = crypto.randomBytes(16);
      await insertUser({ username, userId, allowedDevices: ['device123'] });
      user = await getUser(username);
    } else {
      const creds = await getCredentials(username);
      if (creds.length > 0) {
        return res.status(400).json({ message: 'User already exists' });
      }
    }

    const rawUserId = user.userId;
    console.log('[WEBAUTHN REGISTER] userId typeof:', typeof rawUserId, 'isBuffer:', Buffer.isBuffer(rawUserId));
    const userIdBuffer = Buffer.isBuffer(rawUserId) ? rawUserId : Buffer.from(rawUserId);
    console.log('[WEBAUTHN REGISTER] userId length:', userIdBuffer.length);

    let options;
    try {
      options = generateRegistrationOptions({
        rpName,
        rpID,
        userID: userIdBuffer,
        userName: username,
        attestationType: 'none',
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'preferred',
        },
      });
    } catch (e) {
      console.warn('[WEBAUTHN REGISTER] generateRegistrationOptions threw, falling back:', e.message);
    }

    if (!options || !options.challenge || !options.user || !options.user.id) {
      const fallbackChallenge = crypto.randomBytes(32);
      options = {
        rp: { name: rpName, id: rpID },
        user: {
          id: toBase64URL(userIdBuffer),
          name: username,
          displayName: username,
        },
        challenge: toBase64URL(fallbackChallenge),
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
          { alg: -257, type: 'public-key' }, // RS256
        ],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
        excludeCredentials: [],
        extensions: undefined,
      };
      console.log('[WEBAUTHN REGISTER] Using manual fallback options');
    }

    console.log('[WEBAUTHN REGISTER] options keys:', Object.keys(options));
    console.log('[WEBAUTHN REGISTER] options.challenge:', options.challenge);

    challenges.set(username, options.challenge);

    res.json(options);
  } catch (error) {
    console.error('[WEBAUTHN REGISTER] generate options error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Verify registration
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  console.log('[VERIFY REGISTER] username:', username);

  try {
    const user = await getUser(username);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const expectedOrigin = req.headers.origin;
    const expectedChallenge = challenges.get(username);

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    console.log('[VERIFY REGISTER] result:', verification.verified);

    if (verification.verified && verification.registrationInfo) {
      await insertCredential(username, {
        credentialPublicKey: verification.registrationInfo.credentialPublicKey,
        credentialID: verification.registrationInfo.credentialID,
        counter: verification.registrationInfo.counter,
        transports: verification.registrationInfo.transports,
      });
      challenges.delete(username);
      return res.json({ message: 'Registration successful' });
    }

    return res.status(400).json({ message: 'Registration failed' });
  } catch (error) {
    console.error('[VERIFY REGISTER] error:', error);
    return res.status(400).json({ message: error.message });
  }
});

// Login endpoint (mock)
app.post('/login', async (req, res) => { 
  const { username, fingerprint, deviceId } = req.body; 
  console.log('[LOGIN] payload:', { username, deviceId });
  
  if (!username || !fingerprint || !deviceId) { 
    return res.status(400).json({ message: 'Missing required fields' }); 
  } 
  
  try {
    const user = await getUser(username);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const allowedDevices = JSON.parse(user.allowedDevices || '[]');
    const isFingerprintValid = user.fingerprintHash && (hashFingerprint(fingerprint) === user.fingerprintHash);
    const isDeviceValid = allowedDevices.includes(deviceId);

    if (isFingerprintValid && isDeviceValid) {
      return res.json({ message: 'Login successful' });
    } else if (isFingerprintValid && !isDeviceValid) {
      allowedDevices.push(deviceId);
      await updateAllowedDevices(username, allowedDevices);
      return res.json({ message: 'Login successful on new device' });
    }

    return res.status(401).json({ message: 'Authentication failed' });
  } catch (err) {
    console.error('[LOGIN] error:', err);
    res.status(500).json({ message: 'Server error' });
  }
}); 

// Login endpoint for WebAuthn
app.post('/login-webauthn', async (req, res) => {
  const { username } = req.body;
  console.log('[WEBAUTHN LOGIN] username:', username);

  try {
    const user = await getUser(username);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const creds = await getCredentials(username);
    if (creds.length === 0) {
      return res.status(400).json({ message: 'No credentials registered' });
    }

    const options = generateAuthenticationOptions({
      allowCredentials: creds.map(cred => ({
        id: cred.credentialID, // Buffer
        type: 'public-key',
        transports: cred.transports ? JSON.parse(cred.transports) : undefined,
      })),
      userVerification: 'required',
    });

    challenges.set(username, options.challenge);
    console.log('[WEBAUTHN LOGIN] challenge:', options.challenge);

    res.json(options);
  } catch (error) {
    console.error('[WEBAUTHN LOGIN] generate options error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Verify authentication
app.post('/verify-authentication', async (req, res) => {
  const { username, response, deviceId } = req.body;
  console.log('[VERIFY LOGIN] username:', username, 'deviceId:', deviceId);

  try {
    const user = await getUser(username);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const creds = await getCredentials(username);
    if (creds.length === 0) {
      return res.status(400).json({ message: 'No credentials registered' });
    }

    // Optionally, pick the matching credential by rawId; for simplicity, use first
    const authenticator = {
      credentialID: creds[0].credentialID,
      credentialPublicKey: creds[0].credentialPublicKey,
      counter: creds[0].counter,
      transports: creds[0].transports ? JSON.parse(creds[0].transports) : undefined,
    };

    const expectedOrigin = req.headers.origin;
    const expectedChallenge = challenges.get(username);

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator,
    });

    console.log('[VERIFY LOGIN] result:', verification.verified);

    if (!verification.verified) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // Update device list if needed
    const allowedDevices = JSON.parse(user.allowedDevices || '[]');
    if (!allowedDevices.includes(deviceId)) {
      allowedDevices.push(deviceId);
      await updateAllowedDevices(username, allowedDevices);
    }

    challenges.delete(username);
    return res.json({ message: allowedDevices.includes(deviceId) ? 'Login successful' : 'Login successful on new device' });
  } catch (error) {
    console.error('[VERIFY LOGIN] error:', error);
    return res.status(400).json({ message: error.message });
  }
});
  
app.listen(port, () => { 
  console.log(`Server running at http://localhost:${port}`); 
});
