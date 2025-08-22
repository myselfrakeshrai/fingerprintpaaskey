import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import SplineScene from '../components/SplineScene';
import { getDeviceFingerprintHash } from '../utils/fp';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [fingerprintHash, setFingerprintHash] = useState('');
  const [passwordToken, setPasswordToken] = useState('');
  const [hint, setHint] = useState('');
  const [status, setStatus] = useState('');
  const [statusColor, setStatusColor] = useState('');
  const deviceId = 'device123';

  const loginPassword = async () => {
    setStatus('');
    setStatusColor('');
    try {
      if (!username || !password) {
        setStatus('Enter username and password');
        setStatusColor('text-red-600');
        return;
      }
      setHint('Verifying password...');
      const resp = await fetch('/login-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await resp.json();
      setHint('');
      if (resp.ok && data.passwordToken) {
        setPasswordToken(data.passwordToken);
        setStatus('Password OK. Provide fingerprint to complete 2FA.');
        setStatusColor('text-green-700');
      } else {
        setPasswordToken('');
        setStatus(data.message || 'Password failed');
        setStatusColor('text-red-600');
      }
    } catch (e) {
      setHint('');
      setPasswordToken('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-600');
    }
  };

  const verifyFingerprint = async () => {
    setStatus('');
    setStatusColor('');
    try {
      if (!passwordToken) {
        setStatus('Run password step first');
        setStatusColor('text-red-600');
        return;
      }
      if (!fingerprint && !fingerprintHash) {
        setStatus('Enter fingerprint or capture device hash');
        setStatusColor('text-red-600');
        return;
      }
      setHint('Verifying fingerprint...');
      const resp = await fetch('/verify-fingerprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, fingerprint, fingerprintHash, deviceId, passwordToken }),
      });
      const data = await resp.json();
      setHint('');
      setStatus(data.message || (resp.ok ? '2FA successful' : '2FA failed'));
      setStatusColor(resp.ok ? 'text-green-700' : 'text-red-600');
      if (resp.ok) setPasswordToken('');
    } catch (e) {
      setHint('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-600');
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden">
      <div className="absolute inset-0 -z-10">
        {process.env.REACT_APP_SPLINE_SCENE_URL ? (
          <SplineScene
            sceneUrl={process.env.REACT_APP_SPLINE_SCENE_URL}
            className="w-full h-full block"
          />
        ) : null}
      </div>
      <div className="absolute inset-0 -z-0 bg-black/50 backdrop-blur-sm" />

      <div className="relative z-10 w-full min-h-screen flex items-center justify-center text-black">
        <div className="w-full max-w-md bg-white border border-black/10 rounded-lg p-8 shadow-xl">
          <h1 className="text-2xl font-bold mb-6 text-center">Login</h1>
          <div className="space-y-3 mb-4">
            <input
              type="text"
              placeholder="Username"
              className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="flex gap-2">
              <button
                onClick={loginPassword}
                className="flex-1 bg-black text-white px-4 py-3 rounded hover:bg-gray-900"
              >
                Login (password)
              </button>
            </div>
          </div>

          <div className="space-y-3 mb-4">
            <input
              type="text"
              placeholder="Fingerprint"
              className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
              value={fingerprint}
              onChange={(e) => setFingerprint(e.target.value)}
            />
            <div className="grid grid-cols-2 gap-3">
              <input
                type="text"
                placeholder="Fingerprint Hash (from device)"
                className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
                value={fingerprintHash}
                onChange={(e) => setFingerprintHash(e.target.value)}
              />
              <button
                type="button"
                onClick={async () => {
                  const h = await getDeviceFingerprintHash();
                  if (h) setFingerprintHash(h);
                }}
                className="bg-black text-white px-4 py-3 rounded hover:bg-gray-900"
              >
                Capture Hash
              </button>
            </div>
            <button
              onClick={verifyFingerprint}
              className="w-full bg-black text-white px-4 py-3 rounded hover:bg-gray-900"
            >
              Verify Fingerprint 2FA
            </button>
          </div>

          {hint && <div className="text-sm text-black mb-2">{hint}</div>}
          {status && <div className={`text-center font-medium ${statusColor}`}>{status}</div>}

          <div className="mt-6 text-center">
            <span className="mr-2">New here?</span>
            <Link to="/register" className="inline-block bg-black text-white px-4 py-2 rounded hover:bg-gray-900">Register</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;


