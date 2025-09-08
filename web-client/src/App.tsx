import React from 'react';
import { Link } from 'react-router-dom';

const HomePage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="max-w-4xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <h1 className="text-xl font-semibold text-gray-900">SecureAuth</h1>
            <nav className="flex space-x-4">
              <Link to="/register" className="text-gray-600 hover:text-gray-900 text-sm">
                Register
              </Link>
              <Link to="/login" className="text-gray-600 hover:text-gray-900 text-sm">
                Login
              </Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Fingerprint Authentication
          </h1>
          <p className="text-gray-600 mb-8">
            Secure, fast, and password-free authentication using WebAuthn technology.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link 
              to="/register" 
              className="bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 transition-colors"
            >
              Register
            </Link>
            <Link 
              to="/login" 
              className="bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-gray-50 transition-colors border border-blue-600"
            >
              Login
            </Link>
          </div>
        </div>

        {/* Simple Features */}
        <div className="grid md:grid-cols-3 gap-6 mb-12">
          <div className="bg-white p-6 rounded-lg border">
            <div className="text-2xl mb-3">🔒</div>
            <h3 className="font-semibold text-gray-900 mb-2">Secure</h3>
            <p className="text-sm text-gray-600">
              Your fingerprint is unique and cannot be replicated.
            </p>
          </div>
          
          <div className="bg-white p-6 rounded-lg border">
            <div className="text-2xl mb-3">⚡</div>
            <h3 className="font-semibold text-gray-900 mb-2">Fast</h3>
            <p className="text-sm text-gray-600">
              Authenticate in seconds with just a touch.
            </p>
          </div>
          
          <div className="bg-white p-6 rounded-lg border">
            <div className="text-2xl mb-3">🌐</div>
            <h3 className="font-semibold text-gray-900 mb-2">Universal</h3>
            <p className="text-sm text-gray-600">
              Works across all modern browsers and devices.
            </p>
          </div>
        </div>

        {/* How It Works */}
        <div className="bg-white rounded-lg border p-6">
          <h2 className="text-xl font-semibold text-center text-gray-900 mb-6">How It Works</h2>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="bg-blue-100 w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3">
                <span className="text-lg font-bold text-blue-600">1</span>
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Register</h3>
              <p className="text-sm text-gray-600">
                Create account and register your fingerprint.
              </p>
            </div>
            
            <div className="text-center">
              <div className="bg-blue-100 w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3">
                <span className="text-lg font-bold text-blue-600">2</span>
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Login</h3>
              <p className="text-sm text-gray-600">
                Touch your fingerprint sensor to access.
              </p>
            </div>
            
            <div className="text-center">
              <div className="bg-blue-100 w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3">
                <span className="text-lg font-bold text-blue-600">3</span>
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Access</h3>
              <p className="text-sm text-gray-600">
                Enjoy secure, password-free access.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default HomePage;
