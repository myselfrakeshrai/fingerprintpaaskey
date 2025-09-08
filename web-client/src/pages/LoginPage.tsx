import React, { useState } from 'react';
import {
  startAuthentication,
} from '@simplewebauthn/browser';
import { Link, useNavigate } from 'react-router-dom';

interface LoginFormData {
  email: string;
  deviceId: string;
  token: string;
}

interface StatusState {
  message: string;
  color: string;
}

interface LoginMode {
  type: 'fingerprint' | 'token';
}

const LoginPage: React.FC = () => {
  const [formData, setFormData] = useState<LoginFormData>({
    email: '',
    deviceId: 'device123',
    token: ''
  });
  const [status, setStatus] = useState<StatusState>({ message: '', color: '' });
  const [hint, setHint] = useState<string>('');
  const [loginMode, setLoginMode] = useState<LoginMode>({ type: 'fingerprint' });
  const navigate = useNavigate();

  const handleInputChange = (field: keyof LoginFormData, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const loginWithFingerprint = async (): Promise<void> => {
    const { email, deviceId } = formData;
    
    if (!email) {
      setStatus({ message: 'Please enter your email', color: 'text-red-500' });
      return;
    }

    // Use email as username for the backend
    const username = email;

    try {
      setHint('Preparing security prompt...');
      const optionsResp = await fetch('/login-webauthn', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const options = await optionsResp.json();
      if (!optionsResp.ok) {
        setHint('');
        setStatus({ 
          message: options?.message || 'Login options failed', 
          color: 'text-red-500' 
        });
        return;
      }

      setHint('Touch your fingerprint sensor now...');
      const attResp = await startAuthentication(options);

      setHint('Fingerprint detected. Verifying...');
      const verificationResp = await fetch('/verify-authentication', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, response: attResp, deviceId }),
      });
      const result = await verificationResp.json();
      setHint('');
      setStatus({ 
        message: result.message || (verificationResp.ok ? 'Login successful' : 'Authentication failed'),
        color: verificationResp.ok ? 'text-green-500' : 'text-red-500'
      });
      
      if (verificationResp.ok) {
        handleSuccessfulLogin(email, deviceId);
      }
    } catch (error) {
      setHint('');
      const name = (error as Error)?.name || '';
      if (name === 'NotAllowedError') {
        setStatus({ message: 'Authentication canceled or timed out', color: 'text-red-500' });
      } else {
        setStatus({ 
          message: 'Error: ' + ((error as Error)?.message || String(error)), 
          color: 'text-red-500' 
        });
      }
    }
  };

  const loginWithToken = async (): Promise<void> => {
    const { email, deviceId, token } = formData;
    
    if (!email || !token) {
      setStatus({ message: 'Please enter your email and token', color: 'text-red-500' });
      return;
    }

    try {
      setHint('Verifying token...');
      const response = await fetch('/login-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, token, deviceId }),
      });
      const result = await response.json();
      setHint('');
      setStatus({ 
        message: result.message || (response.ok ? 'Token login successful' : 'Token authentication failed'),
        color: response.ok ? 'text-green-500' : 'text-red-500'
      });
      
      if (response.ok) {
        handleSuccessfulLogin(email, deviceId);
      }
    } catch (error) {
      setHint('');
      setStatus({ 
        message: 'Error: ' + ((error as Error)?.message || String(error)), 
        color: 'text-red-500' 
      });
    }
  };

  const handleSuccessfulLogin = (email: string, deviceId: string): void => {
    // Save authentication session to localStorage
    const authSession = {
      isAuthenticated: true,
      user: {
        email: email,
        deviceId: deviceId
      },
      loginTime: new Date().toISOString(),
      lastActivity: new Date().toISOString()
    };
    localStorage.setItem('authSession', JSON.stringify(authSession));
    
    // Clear form and redirect to dashboard
    setFormData({
      email: '',
      deviceId: 'device123',
      token: ''
    });
    
    // Redirect to dashboard after a short delay
    setTimeout(() => {
      navigate('/dashboard');
    }, 1500);
  };

  const login = async (): Promise<void> => {
    if (loginMode.type === 'fingerprint') {
      await loginWithFingerprint();
    } else {
      await loginWithToken();
    }
  };


  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="max-w-4xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <Link to="/" className="text-xl font-semibold text-gray-900">SecureAuth</Link>
            <Link to="/register" className="text-gray-600 hover:text-gray-900 text-sm">
              Register
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-md mx-auto px-4 py-12">
        <div className="bg-white rounded-lg border p-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">Login</h1>

          {/* Login Mode Toggle */}
          <div className="mb-6">
            <div className="flex bg-gray-100 rounded-lg p-1">
              <button
                onClick={() => setLoginMode({ type: 'fingerprint' })}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  loginMode.type === 'fingerprint'
                    ? 'bg-white text-blue-600 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                🔐 Fingerprint
              </button>
              <button
                onClick={() => setLoginMode({ type: 'token' })}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  loginMode.type === 'token'
                    ? 'bg-white text-blue-600 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                🔑 Token
              </button>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                type="email"
                placeholder="Enter your email"
                className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={formData.email}
                onChange={(e) => handleInputChange('email', e.target.value)}
              />
            </div>

            {loginMode.type === 'token' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Backup Token
                </label>
                <input
                  type="text"
                  placeholder="Enter your backup token (7 words separated by spaces)"
                  className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  value={formData.token}
                  onChange={(e) => handleInputChange('token', e.target.value)}
                />
                <p className="text-sm text-gray-500 mt-1">
                  Use the token you received during registration
                </p>
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Device ID
              </label>
              <select
                className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={formData.deviceId}
                onChange={(e) => handleInputChange('deviceId', e.target.value)}
              >
                <option value="device123">Current Device (device123)</option>
                <option value="newdevice456">New Device (newdevice456)</option>
              </select>
            </div>

            <button
              onClick={login}
              className="w-full bg-blue-600 text-white p-3 rounded-lg hover:bg-blue-700 font-medium"
            >
              {loginMode.type === 'fingerprint' ? 'Login with Fingerprint' : 'Login with Token'}
            </button>
          </div>

          {/* Forgot Token Section */}
          <div className="mt-4 pt-4 border-t border-gray-200 text-center">
            <Link
              to="/forgottoken"
              className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
            >
              Forgot your token?
            </Link>
          </div>

          {hint && (
            <div className="text-center text-blue-600 font-medium mt-4">{hint}</div>
          )}
          <div className={`text-center font-semibold mt-4 ${status.color}`}>
            {status.message}
          </div>
        </div>
      </main>
    </div>
  );
};

export default LoginPage;
