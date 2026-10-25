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

# Add backend directory to sys.path so app modules are discoverable
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

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


def run_server():
    """Run uvicorn server in background thread."""
    try:
        import uvicorn
        from app.main import app
        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
    except Exception as exc:
        print(f"[ERROR] Could not start local backend server: {exc}", file=sys.stderr)


def wait_for_server(timeout=10):
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


def main():
    print("=" * 60)
    print("   วิถีป้องกันรอบด้าน - Security Workspace Desktop App")
    print("=" * 60)
    print(f"[*] กำลังเริ่มต้นระบบเซิร์ฟเวอร์ในเครื่องที่ {URL} ...")

    # Start server in daemon thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait for server readiness
    if not wait_for_server():
        print("[!] ไม่สามารถเริ่มเซิร์ฟเวอร์ได้ทันเวลา กำลังลองเปิดหน้าต่างโดยตรง...")

    print("[*] เซิร์ฟเวอร์พร้อมใช้งาน! กำลังเปิดหน้าต่าง Desktop App...")

    browser_bin = find_browser_app_executable()
    if browser_bin:
        args = [
            browser_bin,
            f"--app={URL}",
            "--window-size=1280,850",
            "--new-window",
        ]
        try:
            proc = subprocess.Popen(args)
            print("[✓] เปิดหน้าต่าง Desktop สำเร็จ! คุณสามารถสแกน Wi-Fi จริงจากเครื่องได้ทันที")
            print("[*] (ปิดหน้าต่างโปรแกรมเพื่อออกจากระบบ)")
            proc.wait()
            return
        except Exception as err:
            print(f"[!] ไม่สามารถเปิดในโหมด App ได้: {err}")

    # Fallback to default browser
    webbrowser.open(URL)
    print("[✓] เปิดหน้าต่างเบราว์เซอร์สำเร็จ! กด Ctrl+C เพื่อออกจากโปรแกรม")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] ปิดโปรแกรมเรียบร้อยแล้ว")


if __name__ == "__main__":
    main()
