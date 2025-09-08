import React, { useState } from 'react';
import { Link } from 'react-router-dom';

interface StatusState {
  message: string;
  color: string;
}

const ForgotTokenPage: React.FC = () => {
  const [email, setEmail] = useState<string>('');
  const [status, setStatus] = useState<StatusState>({ message: '', color: '' });
  const [isSendingEmail, setIsSendingEmail] = useState<boolean>(false);

  const handleForgotToken = async (): Promise<void> => {
    if (!email) {
      setStatus({ message: 'Please enter your email', color: 'text-red-500' });
      return;
    }

    setIsSendingEmail(true);
    try {
      const response = await fetch('/forgot-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const result = await response.json();
      
      if (response.ok) {
        setStatus({ 
          message: result.message || 'Token sent to your email', 
          color: 'text-green-500' 
        });
        setEmail('');
      } else {
        setStatus({ 
          message: result.message || 'Failed to send token', 
          color: 'text-red-500' 
        });
      }
    } catch (error) {
      setStatus({ 
        message: 'Error sending email. Please try again.', 
        color: 'text-red-500' 
      });
    } finally {
      setIsSendingEmail(false);
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
              Back to Login
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-md mx-auto px-4 py-12">
        <div className="bg-white rounded-lg border p-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">Forgot Your Token?</h1>
          
          <div className="space-y-4">
            <div>
              <p className="text-gray-600 mb-4">
                Enter your email address and we'll send you your backup token.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email Address
              </label>
              <input
                type="email"
                placeholder="Enter your email"
                className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <button
              onClick={handleForgotToken}
              disabled={isSendingEmail}
              className="w-full bg-blue-600 text-white p-3 rounded-lg hover:bg-blue-700 font-medium disabled:opacity-50"
            >
              {isSendingEmail ? 'Sending...' : 'Send Token'}
            </button>
          </div>

          <div className={`text-center font-semibold mt-4 ${status.color}`}>
            {status.message}
          </div>

          {/* Help Section */}
          <div className="mt-6 pt-6 border-t border-gray-200">
            <h3 className="text-sm font-medium text-gray-900 mb-2">Need Help?</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Make sure you're using the email address you registered with</li>
              <li>• Check your spam folder if you don't receive the email</li>
              <li>• The token contains 7 random words for security</li>
              <li>• You can use this token to login if your fingerprint doesn't work</li>
            </ul>
          </div>

          {/* Back to Login */}
          <div className="mt-6 text-center">
            <Link 
              to="/login" 
              className="text-blue-600 hover:text-blue-800 text-sm font-medium"
            >
              ← Back to Login
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
};

export default ForgotTokenPage;
