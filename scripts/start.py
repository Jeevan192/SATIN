"""Production multi-service launcher for hosted environments (Render, Railway, Linux, Windows).

Starts both the FastAPI REST Backend (127.0.0.1:8000) and the Streamlit Supervisory
Dashboard (0.0.0.0:$PORT) concurrently so the dashboard communicates directly with
the live API rather than relying on static file fallbacks.
"""

import os
import signal
import subprocess
import sys
import time


def main():
    port = os.getenv("PORT", "8501")
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    env = os.environ.copy()
    env["PYTHONPATH"] = root_dir
    env["SATSA_API_URL"] = "http://127.0.0.1:8000"

    print(f"[*] Starting SAT-SA FastAPI Backend on 127.0.0.1:8000...")
    backend_proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "backend.app:app",
            "--host", "127.0.0.1",
            "--port", "8000",
            "--log-level", "info",
        ],
        cwd=root_dir,
        env=env,
    )

    # Wait for backend to initialize
    time.sleep(2.0)

    print(f"[*] Starting SATIN Streamlit Dashboard on 0.0.0.0:{port}...")
    frontend_proc = subprocess.Popen(
        [
            sys.executable, "-m", "streamlit", "run", "dashboard/app.py",
            "--server.port", str(port),
            "--server.address", "0.0.0.0",
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
        ],
        cwd=root_dir,
        env=env,
    )

    def shutdown(signum, frame):
        print("[*] Shutting down services...")
        frontend_proc.terminate()
        backend_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Wait for the frontend to finish
    try:
        frontend_proc.wait()
    finally:
        if backend_proc.poll() is None:
            backend_proc.terminate()


if __name__ == "__main__":
    main()
