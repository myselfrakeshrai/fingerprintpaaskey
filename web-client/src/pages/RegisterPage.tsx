import React, { useState } from 'react';
import {
  startRegistration,
} from '@simplewebauthn/browser';
import { Link, useNavigate } from 'react-router-dom';

interface RegisterFormData {
  firstName: string;
  lastName: string;
  email: string;
  deviceId: string;
}

interface StatusState {
  message: string;
  color: string;
}

interface RegistrationResponse {
  message: string;
  backup_token?: string;
}

const RegisterPage: React.FC = () => {
  const [formData, setFormData] = useState<RegisterFormData>({
    firstName: '',
    lastName: '',
    email: '',
    deviceId: 'device123'
  });
  const [status, setStatus] = useState<StatusState>({ message: '', color: '' });
  const [hint, setHint] = useState<string>('');
  const [backupToken, setBackupToken] = useState<string>('');
  const [showToken, setShowToken] = useState<boolean>(false);
  const navigate = useNavigate();

  const handleInputChange = (field: keyof RegisterFormData, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const register = async (): Promise<void> => {
    const { firstName, lastName, email, deviceId } = formData;
    
    if (!firstName || !lastName || !email) {
      setStatus({ message: 'Please fill in all fields', color: 'text-red-500' });
      return;
    }

    // Use email as username for the backend
    const username = email;

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
        setStatus({ 
          message: options?.message || 'Registration options failed', 
          color: 'text-red-500' 
        });
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
      const result: RegistrationResponse = await verificationResp.json();
      setHint('');
      
      if (verificationResp.ok) {
        setStatus({ 
          message: result.message || 'Registration successful',
          color: 'text-green-500'
        });
        
        // Show backup token
        if (result.backup_token) {
          setBackupToken(result.backup_token);
          setShowToken(true);
        }
        
        // Save authentication session to localStorage
        const authSession = {
          isAuthenticated: true,
          user: {
            email: email,
            firstName: firstName,
            lastName: lastName,
            deviceId: deviceId
          },
          loginTime: new Date().toISOString(),
          lastActivity: new Date().toISOString()
        };
        localStorage.setItem('authSession', JSON.stringify(authSession));
        
        // Clear form on successful registration
        setFormData({
          firstName: '',
          lastName: '',
          email: '',
          deviceId: 'device123'
        });
        
        // Redirect to dashboard after showing token
        setTimeout(() => {
          navigate('/dashboard');
        }, 3000);
      } else {
        setStatus({ 
          message: result.message || 'Registration failed',
          color: 'text-red-500'
        });
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

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="max-w-4xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <Link to="/" className="text-xl font-semibold text-gray-900">SecureAuth</Link>
            <Link to="/login" className="text-gray-600 hover:text-gray-900 text-sm">
              Login
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-md mx-auto px-4 py-12">
        <div className="bg-white rounded-lg border p-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">Register</h1>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                First Name
              </label>
              <input
                type="text"
                placeholder="Enter your first name"
                className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={formData.firstName}
                onChange={(e) => handleInputChange('firstName', e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Last Name
              </label>
              <input
                type="text"
                placeholder="Enter your last name"
                className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={formData.lastName}
                onChange={(e) => handleInputChange('lastName', e.target.value)}
              />
            </div>

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
              onClick={register}
              className="w-full bg-blue-600 text-white p-3 rounded-lg hover:bg-blue-700 font-medium"
            >
              Register with Fingerprint
            </button>
          </div>

          {hint && (
            <div className="text-center text-blue-600 font-medium mt-4">{hint}</div>
          )}
          <div className={`text-center font-semibold mt-4 ${status.color}`}>
            {status.message}
          </div>

          {showToken && backupToken && (
            <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
              <h3 className="text-lg font-semibold text-yellow-800 mb-2">
                🔑 Your Backup Token
              </h3>
              <p className="text-yellow-700 mb-3">
                Save this token! You can use it to login if your fingerprint doesn't work.
              </p>
              <div className="bg-white p-4 rounded border-2 border-yellow-300">
                <span className="font-mono text-lg font-bold text-yellow-800 break-all">{backupToken}</span>
              </div>
              <p className="text-sm text-yellow-600 mt-2">
                ⚠️ Keep this token safe and don't share it with anyone! Token contains 7 random words for enhanced security.
              </p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default RegisterPage;
