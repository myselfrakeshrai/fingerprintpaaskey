import React, { useState } from 'react';
import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';
import { Link } from 'react-router-dom';

function App() {
  const [username, setUsername] = useState('');
  const [loginUsername, setLoginUsername] = useState('');
  const [deviceId, setDeviceId] = useState('device123');
  const [status, setStatus] = useState('');
  const [statusColor, setStatusColor] = useState('');
  const [hint, setHint] = useState('');

  const register = async () => {
    if (!username) {
      setStatus('Please enter username');
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

      setHint('Fingerprint detected. Verifying...');
      const verificationResp = await fetch('/verify-registration', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, response: attResp }),
      });
      const result = await verificationResp.json();
      setHint('');
      setStatus(result.message || (verificationResp.ok ? 'Registration successful' : 'Registration failed'));
      setStatusColor(verificationResp.ok ? 'text-green-500' : 'text-red-500');
    } catch (error) {
      setHint('');
      const name = error?.name || '';
      if (name === 'NotAllowedError') {
        setStatus('Authentication canceled or timed out');
      } else {
        setStatus('Error: ' + (error?.message || String(error)));
      }
      setStatusColor('text-red-500');
    }
  };

  const login = async () => {
    if (!loginUsername) {
      setStatus('Please enter username');
      setStatusColor('text-red-500');
      return;
    }

    try {
      setHint('Preparing security prompt...');
      const optionsResp = await fetch('/login-webauthn', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername }),
      });
      const options = await optionsResp.json();
      if (!optionsResp.ok) {
        setHint('');
        setStatus(options?.message || 'Login options failed');
        setStatusColor('text-red-500');
        return;
      }

      setHint('Touch your fingerprint sensor now...');
      const attResp = await startAuthentication(options);

      setHint('Fingerprint detected. Verifying...');
      const verificationResp = await fetch('/verify-authentication', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, response: attResp, deviceId }),
      });
      const result = await verificationResp.json();
      setHint('');
      setStatus(result.message || (verificationResp.ok ? 'Login successful' : 'Authentication failed'));
      setStatusColor(verificationResp.ok ? 'text-green-500' : 'text-red-500');
    } catch (error) {
      setHint('');
      const name = error?.name || '';
      if (name === 'NotAllowedError') {
        setStatus('Authentication canceled or timed out');
      } else {
        setStatus('Error: ' + (error?.message || String(error)));
      }
      setStatusColor('text-red-500');
    }
  };

  return (
    <div className="bg-gray-100 flex items-center justify-center min-h-screen">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <div className="flex justify-end mb-2">
          <Link to="/fingerprinttest" className="text-sm text-blue-600 hover:underline">Go to Fingerprint Test</Link>
        </div>
        <h1 className="text-2xl font-bold text-center mb-6">Fingerprint-Based 2FA</h1>

        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Register</h2>
          <input
            type="text"
            placeholder="Enter username"
            className="w-full p-2 mb-4 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <button
            onClick={register}
            className="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700"
          >
            Register
          </button>
        </div>

        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Login</h2>
          <input
            type="text"
            placeholder="Enter username"
            className="w-full p-2 mb-4 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={loginUsername}
            onChange={(e) => setLoginUsername(e.target.value)}
          />
          <select
            className="w-full p-2 mb-4 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
          >
            <option value="device123">Current Device (device123)</option>
            <option value="newdevice456">New Device (newdevice456)</option>
          </select>
          <button
            onClick={login}
            className="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700"
          >
            Login
          </button>
        </div>

        {hint && (
          <div className="text-center text-blue-600 font-medium mb-2">{hint}</div>
        )}
        <div className={`text-center font-semibold ${statusColor}`}>
          {status}
        </div>
      </div>
    </div>
  );
}

export default App;
