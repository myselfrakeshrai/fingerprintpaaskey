#!/usr/bin/env python3
"""
Cross-platform server startup script for Windows and macOS
"""
import os
import sys
import platform
import subprocess
import time
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required. Current version:", sys.version)
        return False
    print(f"✅ Python {sys.version.split()[0]} detected")
    return True

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = ['flask', 'flask_cors', 'webauthn', 'python-dotenv']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_packages)
            print("✅ Dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            return False
    else:
        print("✅ All dependencies are installed")
    
    return True

def get_server_config():
    """Get server configuration based on platform"""
    system = platform.system().lower()
    
    if system == "windows":
        return {
            "host": "127.0.0.1",
            "port": 5000,
            "debug": True
        }
    elif system == "darwin":  # macOS
        return {
            "host": "0.0.0.0",  # macOS sometimes needs 0.0.0.0
            "port": 5000,
            "debug": True
        }
    else:  # Linux or other
        return {
            "host": "127.0.0.1",
            "port": 5000,
            "debug": True
        }

def start_server():
    """Start the Flask server"""
    print(f"🚀 Starting server on {platform.system()}...")
    
    if not check_python_version():
        return False
    
    if not check_dependencies():
        return False
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Get server configuration
    config = get_server_config()
    
    print(f"📡 Server will run on http://{config['host']}:{config['port']}")
    print("🌐 CORS enabled for React development server")
    print("🔒 WebAuthn fingerprint authentication ready")
    print("\n" + "="*50)
    print("Press Ctrl+C to stop the server")
    print("="*50 + "\n")
    
    # Set environment variables
    os.environ['HOST'] = config['host']
    os.environ['PORT'] = str(config['port'])
    os.environ['DEBUG'] = str(config['debug'])
    
    # Import and run the Flask app
    try:
        from app import app
        app.run(
            host=config['host'],
            port=config['port'],
            debug=config['debug']
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
        return True
    except Exception as e:
        print(f"❌ Server error: {e}")
        return False

if __name__ == "__main__":
    success = start_server()
    sys.exit(0 if success else 1)
