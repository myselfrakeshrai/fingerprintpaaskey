import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  startAuthentication,
} from '@simplewebauthn/browser';

interface User {
  email: string;
  firstName?: string;
  lastName?: string;
  deviceId: string;
  backupToken?: string;
}

interface AuthSession {
  isAuthenticated: boolean;
  user: User | null;
  loginTime: string;
  lastActivity: string;
}

interface StatusState {
  message: string;
  color: string;
}

const DashboardPage: React.FC = () => {
  const [authSession, setAuthSession] = useState<AuthSession | null>(null);
  const [status, setStatus] = useState<StatusState>({ message: '', color: '' });
  const [hint, setHint] = useState<string>('');
  const [isReauthenticating, setIsReauthenticating] = useState<boolean>(false);
  const [backupToken, setBackupToken] = useState<string>('');
  const [showToken, setShowToken] = useState<boolean>(false);
  const [isRegenerating, setIsRegenerating] = useState<boolean>(false);
  const navigate = useNavigate();

  // Load authentication session from localStorage on component mount
  useEffect(() => {
    const savedSession = localStorage.getItem('authSession');
    if (savedSession) {
      try {
        const session: AuthSession = JSON.parse(savedSession);
        setAuthSession(session);
        
        // Fetch backup token if user exists
        if (session.user?.email) {
          fetchBackupToken(session.user.email);
        }
      } catch (error) {
        console.error('Error parsing saved session:', error);
        localStorage.removeItem('authSession');
        navigate('/login');
      }
    } else {
      navigate('/login');
    }
  }, [navigate]);

  // Fetch backup token from server
  const fetchBackupToken = async (email: string): Promise<void> => {
    try {
      const encodedEmail = encodeURIComponent(email);
      const response = await fetch(`/get-backup-token/${encodedEmail}`);
      if (response.ok) {
        const data = await response.json();
        setBackupToken(data.token || '');
      } else {
        console.error('Failed to fetch backup token:', response.status);
      }
    } catch (error) {
      console.error('Error fetching backup token:', error);
    }
  };

  // Regenerate backup token
  const regenerateToken = async (): Promise<void> => {
    if (!authSession?.user?.email) return;

    setIsRegenerating(true);
    try {
      const response = await fetch('/regenerate-backup-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: authSession.user.email }),
      });
      const result = await response.json();
      
      if (response.ok) {
        setBackupToken(result.token || '');
        setStatus({ 
          message: 'Token regenerated successfully!', 
          color: 'text-green-500' 
        });
      } else {
        setStatus({ 
          message: result.message || 'Failed to regenerate token', 
          color: 'text-red-500' 
        });
      }
    } catch (error) {
      setStatus({ 
        message: 'Error regenerating token', 
        color: 'text-red-500' 
      });
    } finally {
      setIsRegenerating(false);
    }
  };

  // Update last activity time
  const updateLastActivity = () => {
    if (authSession) {
      const updatedSession = {
        ...authSession,
        lastActivity: new Date().toISOString()
      };
      setAuthSession(updatedSession);
      localStorage.setItem('authSession', JSON.stringify(updatedSession));
    }
  };

  // Re-authenticate with fingerprint
  const reauthenticate = async (): Promise<void> => {
    if (!authSession?.user) return;

    setIsReauthenticating(true);
    const { email, deviceId } = authSession.user;
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
          message: options?.message || 'Authentication options failed', 
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
      
      if (verificationResp.ok) {
        setStatus({ 
          message: 'Re-authentication successful!', 
          color: 'text-green-500' 
        });
        // Update session with new login time
        const updatedSession = {
          ...authSession,
          loginTime: new Date().toISOString(),
          lastActivity: new Date().toISOString()
        };
        setAuthSession(updatedSession);
        localStorage.setItem('authSession', JSON.stringify(updatedSession));
      } else {
        setStatus({ 
          message: result.message || 'Re-authentication failed', 
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
    } finally {
      setIsReauthenticating(false);
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('authSession');
    navigate('/login');
  };

  // Format date for display
  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  };

  // Calculate session duration
  const getSessionDuration = (): string => {
    if (!authSession) return '0 minutes';
    const loginTime = new Date(authSession.loginTime);
    const now = new Date();
    const diffMs = now.getTime() - loginTime.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    
    if (diffHours > 0) {
      return `${diffHours}h ${diffMins % 60}m`;
    }
    return `${diffMins}m`;
  };

  if (!authSession) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="border-b border-gray-200">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <h1 className="text-xl font-medium text-gray-900">Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">
                {authSession.user?.firstName || authSession.user?.email || 'User'}
              </span>
              <button
                onClick={logout}
                className="text-sm text-gray-600 hover:text-gray-900 px-3 py-1 border border-gray-300 rounded hover:bg-gray-50"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Session Info */}
        <div className="border border-gray-200 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Session Information</h2>
          <div className="grid md:grid-cols-3 gap-4">
            <div className="border border-gray-200 p-4 rounded">
              <h3 className="text-sm font-medium text-gray-600 mb-1">Duration</h3>
              <p className="text-lg font-medium text-gray-900">{getSessionDuration()}</p>
            </div>
            <div className="border border-gray-200 p-4 rounded">
              <h3 className="text-sm font-medium text-gray-600 mb-1">Login Time</h3>
              <p className="text-sm text-gray-900">{formatDate(authSession.loginTime)}</p>
            </div>
            <div className="border border-gray-200 p-4 rounded">
              <h3 className="text-sm font-medium text-gray-600 mb-1">Last Activity</h3>
              <p className="text-sm text-gray-900">{formatDate(authSession.lastActivity)}</p>
            </div>
          </div>
        </div>

        {/* Authentication Section */}
        <div className="border border-gray-200 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Authentication</h2>
          <p className="text-sm text-gray-600 mb-4">
            Re-authenticate with your fingerprint to extend your session.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={reauthenticate}
              disabled={isReauthenticating}
              className="px-4 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isReauthenticating ? 'Authenticating...' : 'Re-authenticate'}
            </button>
            
            <button
              onClick={updateLastActivity}
              className="px-4 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Update Activity
            </button>
          </div>

          {hint && (
            <div className="text-sm text-gray-600 mt-3">{hint}</div>
          )}
          <div className={`text-sm mt-3 ${status.color}`}>
            {status.message}
          </div>
        </div>

        {/* Backup Token Section */}
        <div className="border border-gray-200 rounded-lg p-6 mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-medium text-gray-900">Backup Token</h2>
            <button
              onClick={regenerateToken}
              disabled={isRegenerating}
              className="px-3 py-1 border border-gray-300 rounded text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {isRegenerating ? 'Regenerating...' : 'Regenerate'}
            </button>
          </div>
          <p className="text-sm text-gray-600 mb-4">
            Use this token to login if your fingerprint doesn't work.
          </p>
          
          {backupToken ? (
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex-1 border border-gray-300 rounded p-3 bg-gray-50">
                  <span className="font-mono text-sm font-medium text-gray-900 break-all">{backupToken}</span>
                </div>
                <button
                  onClick={() => setShowToken(!showToken)}
                  className="px-3 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  {showToken ? 'Hide' : 'Show'}
                </button>
              </div>
              <div className="text-xs text-gray-500">
                {backupToken.split(' ').length === 1 
                  ? 'Old format detected. Click "Regenerate" to get a secure 7-word token.'
                  : 'Token contains 7 random words for enhanced security'
                }
              </div>
            </div>
          ) : (
            <div className="text-sm text-gray-500">Loading token...</div>
          )}
          
          {showToken && backupToken && (
            <div className="mt-3 p-3 bg-gray-50 border border-gray-200 rounded">
              <p className="text-xs text-gray-600">
                Keep this token safe. You can use it to login at any time.
              </p>
            </div>
          )}
        </div>

        {/* User Information */}
        <div className="border border-gray-200 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Account Information</h2>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Email</label>
              <p className="text-sm text-gray-900">{authSession.user?.email || 'N/A'}</p>
            </div>
            {authSession.user?.firstName && (
              <div>
                <label className="block text-sm font-medium text-gray-600 mb-1">First Name</label>
                <p className="text-sm text-gray-900">{authSession.user.firstName}</p>
              </div>
            )}
            {authSession.user?.lastName && (
              <div>
                <label className="block text-sm font-medium text-gray-600 mb-1">Last Name</label>
                <p className="text-sm text-gray-900">{authSession.user.lastName}</p>
              </div>
            )}
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Device ID</label>
              <p className="text-sm text-gray-900">{authSession.user?.deviceId || 'N/A'}</p>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="border border-gray-200 rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h2>
          <div className="flex flex-wrap gap-3">
            <Link
              to="/fingerprinttest"
              className="px-4 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Test Fingerprint
            </Link>
            
            <button
              onClick={reauthenticate}
              disabled={isReauthenticating}
              className="px-4 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Re-authenticate
            </button>
            
            <button
              onClick={logout}
              className="px-4 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Logout
            </button>
          </div>
        </div>
      </main>
    </div>
  );
};

export default DashboardPage;
