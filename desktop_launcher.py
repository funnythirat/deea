"""
Desktop Application Launcher for Security Workspace (วิถีป้องกันรอบด้าน)
Starts the local backend server and opens the application in a standalone native Desktop Window.
"""
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

# Safe encoding configuration for Windows consoles
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Root directory configuration
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Use local SQLite database by default for Desktop App mode
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "scanner.db"
os.environ.setdefault("DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")

PORT = 8000
HOST = "127.0.0.1"
URL = f"http://{HOST}:{PORT}"


def find_browser_app_executable():
    """Find Microsoft Edge or Google Chrome to launch in standalone App mode."""
    candidates = [
        shutil.which("msedge"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        shutil.which("chrome"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def wait_for_server(timeout=15):
    """Wait until local server starts responding."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"{URL}/", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def launch_browser_window():
    """Wait for server to be ready, then open Edge/Chrome in standalone App mode."""
    if not wait_for_server():
        print("[!] Server startup took longer than expected. Opening browser now...", flush=True)

    print("[*] Server is ready! Opening Desktop App Window...", flush=True)
    browser_bin = find_browser_app_executable()
    if browser_bin:
        args = [
            browser_bin,
            f"--app={URL}",
            "--window-size=1280,850",
            "--new-window",
        ]
        try:
            subprocess.Popen(args)
            print("[✓] Desktop Window opened successfully!", flush=True)
            print("[*] You can now scan real Wi-Fi directly in the window.", flush=True)
            print("[*] Leave this console window open while using the app.", flush=True)
            print("[*] Press Ctrl+C to stop the server when finished.", flush=True)
            return
        except Exception as err:
            print(f"[!] Could not open in app mode: {err}", flush=True)

    # Fallback to system default browser
    webbrowser.open(URL)
    print("[✓] Browser window opened! Leave this console open while using.", flush=True)


def main():
    print("=" * 60, flush=True)
    print("   Security Workspace - Desktop Application Launcher", flush=True)
    print("=" * 60, flush=True)
    print(f"[*] Starting local server on {URL} ...", flush=True)

    # Launch browser window asynchronously once server responds
    launcher_thread = threading.Thread(target=launch_browser_window, daemon=True)
    launcher_thread.start()

    # Run uvicorn directly in main thread so process stays alive
    try:
        import uvicorn
        from app.main import app

        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
    except KeyboardInterrupt:
        print("\n[*] Application shutdown requested. Goodbye!", flush=True)
    except Exception as exc:
        print(f"\n[ERROR] Server failed to run: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
