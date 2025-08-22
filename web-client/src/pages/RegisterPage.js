import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { getDeviceFingerprintHash } from '../utils/fp';

const RegisterPage = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [fingerprintHash, setFingerprintHash] = useState('');
  const captureDeviceHash = async () => {
    const h = await getDeviceFingerprintHash();
    if (h) setFingerprintHash(h);
  };
  const [hint, setHint] = useState('');
  const [status, setStatus] = useState('');
  const [statusColor, setStatusColor] = useState('');

  const register = async () => {
    setStatus('');
    setStatusColor('');
    try {
      if (!username || !email || !password || !confirmPassword || (!fingerprint && !fingerprintHash)) {
        setStatus('Fill all fields');
        setStatusColor('text-red-600');
        return;
      }
      if (password !== confirmPassword) {
        setStatus('Passwords do not match');
        setStatusColor('text-red-600');
        return;
      }
      setHint('Registering...');
      const resp = await fetch('/register-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, fingerprint, fingerprintHash }),
      });
      const data = await resp.json();
      setHint('');
      setStatus(data.message || (resp.ok ? 'Registration successful' : 'Registration failed'));
      setStatusColor(resp.ok ? 'text-green-700' : 'text-red-600');

      // If password+fingerprint registration succeeded, create a passkey using WebAuthn
      if (resp.ok) {
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
            setStatus(options?.message || 'Passkey options failed');
            setStatusColor('text-red-600');
            return;
          }
          setHint('Touch your fingerprint sensor to create passkey...');
          const attResp = await startRegistration(options);
          setHint('Verifying passkey...');
          const verifyResp = await fetch('/verify-registration', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: attResp }),
          });
          const verifyData = await verifyResp.json();
          setHint('');
          setStatus(verifyData.message || (verifyResp.ok ? 'Passkey created' : 'Passkey failed'));
          setStatusColor(verifyResp.ok ? 'text-green-700' : 'text-red-600');
        } catch (e) {
          setHint('');
          setStatus('Passkey error: ' + (e?.message || String(e)));
          setStatusColor('text-red-600');
        }
      }
    } catch (e) {
      setHint('');
      setStatus('Error: ' + (e?.message || String(e)));
      setStatusColor('text-red-600');
    }
  };

  return (
    <div className="min-h-screen bg-white text-black flex items-center justify-center">
      <div className="w-full max-w-md bg-white border border-black/10 rounded-lg p-8">
        <h1 className="text-2xl font-bold mb-6 text-center">Register</h1>
        <div className="space-y-3 mb-4">
          <input
            type="text"
            placeholder="Username"
            className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="email"
            placeholder="Email"
            className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <div className="grid grid-cols-2 gap-3">
            <input
              type="password"
              placeholder="Password"
              className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <input
              type="password"
              placeholder="Confirm Password"
              className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
          <input
            type="text"
            placeholder="Fingerprint"
            className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
            value={fingerprint}
            onChange={(e) => setFingerprint(e.target.value)}
          />
          <input
            type="text"
            placeholder="Fingerprint Hash (from device)"
            className="w-full p-3 border border-black/20 rounded focus:outline-none focus:ring-2 focus:ring-black"
            value={fingerprintHash}
            onChange={(e) => setFingerprintHash(e.target.value)}
          />
          <button type="button" onClick={captureDeviceHash} className="w-full bg-black text-white px-4 py-3 rounded hover:bg-gray-900">Capture Device Fingerprint Hash</button>
          <button onClick={register} className="w-full bg-black text-white px-4 py-3 rounded hover:bg-gray-900">Register</button>
        </div>

        {hint && <div className="text-sm text-black mb-2">{hint}</div>}
        {status && <div className={`text-center font-medium ${statusColor}`}>{status}</div>}

        <div className="mt-6 text-center">
          <span className="mr-2">Already have an account?</span>
          <Link to="/login" className="inline-block bg-black text-white px-4 py-2 rounded hover:bg-gray-900">Login</Link>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;


