#!/usr/bin/env python3
"""
CamShield AI - Quick Start Script
Works on Linux, Windows, macOS
Run: python start.py
"""
import subprocess
import sys
import os
import platform

OS = platform.system().lower()
PY = sys.executable


def run(cmd, **kwargs):
    print(f"  > {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, **kwargs)


def check_prereqs():
    print("\n🔍 Checking prerequisites...")
    ok = True

    # Python
    major, minor = sys.version_info[:2]
    if major < 3 or minor < 10:
        print(f"  ✗ Python 3.10+ required (you have {major}.{minor})")
        ok = False
    else:
        print(f"  ✓ Python {major}.{minor}")

    # Node.js
    try:
        result = run(["node", "--version"], capture_output=True, text=True)
        print(f"  ✓ Node.js {result.stdout.strip()}")
    except FileNotFoundError:
        print("  ✗ Node.js not found — install from https://nodejs.org")
        ok = False

    # nmap
    try:
        run(["nmap", "--version"], capture_output=True)
        print("  ✓ nmap available")
    except FileNotFoundError:
        print("  ⚠ nmap not found — install for full scanning (optional)")

    return ok


def setup_backend():
    print("\n📦 Installing backend dependencies...")
    os.chdir("backend")
    run([PY, "-m", "pip", "install", "-r", "requirements.txt", "-q"])

    # Create .env from example if not exists
    if not os.path.exists(".env"):
        if os.path.exists(".env.example"):
            import shutil
            shutil.copy(".env.example", ".env")
            print("  ✓ Created .env from .env.example")

    os.chdir("..")


def setup_frontend():
    print("\n📦 Installing frontend dependencies...")
    os.chdir("frontend")
    run(["npm", "install", "--silent"])
    os.chdir("..")


def start_dev():
    print("\n🚀 Starting CamShield AI in development mode...")
    print("   Backend:  http://localhost:8000")
    print("   Frontend: http://localhost:3000")
    print("   API docs: http://localhost:8000/docs")
    print("\n   Press Ctrl+C to stop\n")

    # Start
    import threading

    def run_backend():
        os.chdir("backend") if os.path.exists("backend") else None
        subprocess.run([PY, "-m", "app.main"])

    def run_frontend():
        frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
        subprocess.run(["npm", "run", "dev"], cwd=frontend_dir)

    backend_thread = threading.Thread(target=run_backend, daemon=True)
    backend_thread.start()

    run_frontend()


if __name__ == "__main__":
    print("=" * 50)
    print("  🛡️  CamShield AI - Quick Start")
    print("=" * 50)

    if not check_prereqs():
        print("\n❌ Fix the issues above, then run again.")
        sys.exit(1)

    setup_backend()
    setup_frontend()
    start_dev()
