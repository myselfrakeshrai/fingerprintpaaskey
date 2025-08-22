import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const FingerprintTestPage = () => {
  const [username, setUsername] = useState('');
  const [status, setStatus] = useState('');
  const [statusColor, setStatusColor] = useState('');
  const [hint, setHint] = useState('');
  const [detectedName, setDetectedName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [passwordToken, setPasswordToken] = useState('');
  const deviceId = 'device123';

  const promptRegister = async () => {
    if (!username) {
      setStatus('Enter username');
      setStatusColor('text-red-500');
      return;
    }
    try {
      setHint('Preparing security prompt...');
      const optionsResp = await fetch('/register-webauthn', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const options = await optionsResp.json();
      if (!optionsResp.ok) {
        setHint('');
        setStatus(options?.message || 'Registration options failed');
        setStatusColor('text-red-500');
        return;
      }
      setHint('Touch your fingerprint sensor now...');
      const attResp = await startRegistration(options);
      setHint('Finger is placed. Verifying...');
      const verifyResp = await fetch('/verify-registration', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, response: attResp }),
      });
      const result = await verifyResp.json();
      setHint('');
      setStatus(result.message || (verifyResp.ok ? 'Registration successful' : 'Registration failed'));
      setStatusColor(verifyResp.ok ? 'text-green-500' : 'text-red-500');
    } catch (e) {
      setHint('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-500');
    }
  };

  const registerWithPassword = async () => {
    setStatus('');
    setStatusColor('');
    try {
      if (!username || !email || !password || !fingerprint) {
        setStatus('Enter username, email, password, and fingerprint');
        setStatusColor('text-red-500');
        return;
      }
      setHint('Registering password + fingerprint...');
      const resp = await fetch('/register-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, fingerprint }),
      });
      const data = await resp.json();
      setHint('');
      setStatus(data.message || (resp.ok ? 'Registration successful' : 'Registration failed'));
      setStatusColor(resp.ok ? 'text-green-500' : 'text-red-500');
    } catch (e) {
      setHint('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-500');
    }
  };

  const loginPassword = async () => {
    setStatus('');
    setStatusColor('');
    try {
      if (!username || !password) {
        setStatus('Enter username and password');
        setStatusColor('text-red-500');
        return;
      }
      setHint('Verifying password...');
      const resp = await fetch('/login-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await resp.json();
      if (resp.ok && data.passwordToken) {
        setPasswordToken(data.passwordToken);
        setStatus('Password OK. Provide fingerprint to complete 2FA.');
        setStatusColor('text-green-600');
        setHint('');
      } else {
        setPasswordToken('');
        setHint('');
        setStatus(data.message || 'Password failed');
        setStatusColor('text-red-500');
      }
    } catch (e) {
      setHint('');
      setPasswordToken('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-500');
    }
  };

  const verifyFingerprint = async () => {
    setStatus('');
    setStatusColor('');
    try {
      if (!passwordToken) {
        setStatus('Run password step first');
        setStatusColor('text-red-500');
        return;
      }
      if (!fingerprint) {
        setStatus('Enter fingerprint');
        setStatusColor('text-red-500');
        return;
      }
      setHint('Verifying fingerprint...');
      const resp = await fetch('/verify-fingerprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, fingerprint, deviceId, passwordToken }),
      });
      const data = await resp.json();
      setHint('');
      setStatus(data.message || (resp.ok ? '2FA successful' : '2FA failed'));
      setStatusColor(resp.ok ? 'text-green-600' : 'text-red-500');
      if (resp.ok) setPasswordToken('');
    } catch (e) {
      setHint('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-500');
    }
  };

  const fingerprintDiscovery = async () => {
    try {
      setDetectedName('');
      setStatus('');
      setStatusColor('');
      setHint('Preparing fingerprint prompt...');
      const optionsResp = await fetch('/login-webauthn-any', {
        method: 'POST',
      });
      const options = await optionsResp.json();
      if (!optionsResp.ok) {
        setHint('');
        setDetectedName('');
        setStatus('No user with this fingerprint');
        setStatusColor('text-red-500');
        return;
      }
      setHint('Touch your fingerprint sensor now...');
      const assertion = await startAuthentication(options);
      setHint('Finger is placed. Verifying...');
      const verifyResp = await fetch('/verify-authentication-any', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ response: assertion, deviceId: 'device123' }),
      });
      const result = await verifyResp.json();
      setHint('');
      if (verifyResp.ok && result.username) {
        setDetectedName(result.username);
        setStatus('');
      } else {
        setDetectedName('');
        setStatus('No user with this fingerprint');
        setStatusColor('text-red-500');
      }
    } catch (e) {
      setHint('');
      setDetectedName('');
      setStatus('No user with this fingerprint');
      setStatusColor('text-red-500');
    }
  };

  return (
    <div className="bg-gray-100 flex items-center justify-center min-h-screen">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <div className="flex justify-between items-center mb-4">
          <h1 className="text-2xl font-bold">Fingerprint Test</h1>
          <Link to="/" className="text-sm text-blue-600 hover:underline">Back to Home</Link>
        </div>
        <div className="mb-4">
          <input
            type="text"
            placeholder="Enter username (for registration)"
            className="w-full p-2 mb-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="email"
            placeholder="Email (for password registration)"
            className="w-full p-2 mb-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            className="w-full p-2 mb-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <input
            type="text"
            placeholder="Fingerprint (string for demo)"
            className="w-full p-2 mb-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={fingerprint}
            onChange={(e) => setFingerprint(e.target.value)}
          />
          <div className="flex gap-2 mb-2">
            <button onClick={promptRegister} className="bg-blue-600 text-white px-3 py-2 rounded hover:bg-blue-700">Register</button>
            <button onClick={registerWithPassword} className="bg-teal-600 text-white px-3 py-2 rounded hover:bg-teal-700">Register Password+FP</button>
            <button onClick={fingerprintDiscovery} className="bg-purple-600 text-white px-3 py-2 rounded hover:bg-purple-700">Fingerprint</button>
          </div>
          <div className="flex gap-2 mb-2">
            <button onClick={loginPassword} className="bg-gray-800 text-white px-3 py-2 rounded hover:bg-gray-900">Login (password)</button>
            <button onClick={verifyFingerprint} className="bg-green-700 text-white px-3 py-2 rounded hover:bg-green-800">Verify Fingerprint 2FA</button>
          </div>
        </div>
        {hint && <div className="text-blue-600 mb-2">{hint}</div>}
        {detectedName && (
          <div className="text-2xl font-bold text-green-600 text-center">{detectedName}</div>
        )}
        {!detectedName && status && <div className={`font-semibold ${statusColor} text-center`}>{status}</div>}
        <div className="mt-6 text-sm text-gray-600">
          Fingerprint button detects the registered user name via discoverable passkey. If none is found, you'll see a simple message.
        </div>
      </div>
    </div>
  );
};

export default FingerprintTestPage;
