"""
Real System Antivirus & Threat Scanner Engine
Scans real local files and directories on disk using YARA heuristics, signature analysis,
and double-extension detection without requiring files to be uploaded.
"""
import datetime
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yara

from app.config import YARA_RULES_PATH

logger = logging.getLogger(__name__)

# Double extension patterns commonly used by trojans/phishing
DOUBLE_EXT_PATTERN = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|mp3|mp4)\.(exe|scr|bat|cmd|vbs|js|wsf|hta|pif)$",
    re.IGNORECASE,
)

EXCLUDED_DIR_NAMES = {
    "system volume information",
    "$recycle.bin",
    "$windows.~bt",
    "$windows.~ws",
    "windows.old",
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
}

MAX_FILE_SCAN_BYTES = 25 * 1024 * 1024  # 25 MiB


class SystemScanner:
    _instance: Optional["SystemScanner"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.rules: Optional[yara.Rules] = None
        self._load_rules()
        self.is_scanning = False
        self._stop_requested = False
        self._thread: Optional[threading.Thread] = None

        self.state: Dict[str, Any] = {
            "status": "idle",  # idle, scanning, completed, stopped, error
            "mode": "quick",
            "target": "",
            "files_scanned": 0,
            "directories_scanned": 0,
            "current_file": "",
            "threats": [],
            "started_at": None,
            "completed_at": None,
            "elapsed_seconds": 0.0,
            "error": None,
        }

    @classmethod
    def get_instance(cls) -> "SystemScanner":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _load_rules(self) -> None:
        try:
            if YARA_RULES_PATH.is_file():
                rules_text = YARA_RULES_PATH.read_text(encoding="utf-8")
                self.rules = yara.compile(source=rules_text)
                logger.info("SystemScanner: Compiled YARA rules successfully")
            else:
                logger.warning("SystemScanner: YARA rules file not found at %s", YARA_RULES_PATH)
        except Exception as exc:
            logger.exception("SystemScanner: Failed to compile YARA rules: %s", exc)


    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            data = dict(self.state)
            data["threats"] = list(self.state["threats"])
            if self.state["status"] == "scanning" and self.state["started_at"]:
                start_dt = datetime.datetime.fromisoformat(self.state["started_at"])
                data["elapsed_seconds"] = round((datetime.datetime.now(datetime.timezone.utc) - start_dt).total_seconds(), 1)
            return data

    def start_scan(self, mode: str = "quick", custom_path: Optional[str] = None) -> bool:
        with self._lock:
            if self.is_scanning:
                return False

            self.is_scanning = True
            self._stop_requested = False
            self.state = {
                "status": "scanning",
                "mode": mode,
                "target": "",
                "files_scanned": 0,
                "directories_scanned": 0,
                "current_file": "กำลังเริ่มต้นการสแกน...",
                "threats": [],
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "completed_at": None,
                "elapsed_seconds": 0.0,
                "error": None,
            }

            self._thread = threading.Thread(
                target=self._run_scan_worker,
                args=(mode, custom_path),
                daemon=True,
            )
            self._thread.start()
            return True

    def stop_scan(self) -> bool:
        with self._lock:
            if not self.is_scanning:
                return False
            self._stop_requested = True
            self.state["status"] = "stopped"
            self.state["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.is_scanning = False
            return True

    def _get_target_paths(self, mode: str, custom_path: Optional[str]) -> List[Path]:
        targets: List[Path] = []
        home = Path.home()

        if mode == "custom" and custom_path:
            p = Path(custom_path).resolve()
            if p.exists():
                return [p]
            return [home / "Downloads"]

        if mode == "quick":
            quick_dirs = [
                home / "Downloads",
                home / "Desktop",
                home / "Documents",
                Path(os.environ.get("TEMP", str(home / "AppData/Local/Temp"))),
                Path(os.environ.get("APPDATA", str(home / "AppData/Roaming")))
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "Startup",
            ]
            for q in quick_dirs:
                if q.exists() and q.is_dir():
                    targets.append(q)
            return targets

        # Full system scan
        if os.name == "nt":
            # On Windows, scan C:\ drive root
            root = Path("C:\\")
            if root.exists():
                targets.append(root)
            else:
                targets.append(home)
        else:
            targets.append(Path("/"))

        return targets

    def _scan_single_file(self, file_path: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            stat = file_path.stat()
            size = stat.st_size
        except (OSError, PermissionError):
            return findings

        filename = file_path.name

        # 1. Double extension check
        if DOUBLE_EXT_PATTERN.search(filename):
            findings.append({
                "filename": filename,
                "path": str(file_path),
                "threat_name": "Suspicious.DoubleExtension",
                "level": "high",
                "detail": f"ไฟล์ใช้นามสกุลซ้อนเพื่อพรางตัวเป็นเอกสาร/ภาพ ({filename})",
                "recommendation": "อย่าเปิดไฟล์เด็ดขาด ตรวจสอบที่มาของไฟล์หรือลบไฟล์ต้องสงสัย",
            })

        # 2. Check YARA signatures on file content
        if self.rules and size <= MAX_FILE_SCAN_BYTES and size > 0:
            try:
                with file_path.open("rb") as f:
                    file_bytes = f.read(MAX_FILE_SCAN_BYTES)
                matches = self.rules.match(data=file_bytes, timeout=5)

                for match in matches:
                    rule_name = match.rule
                    meta = match.meta or {}
                    desc = meta.get("description", "ตรวจพบพฤติกรรมหรือสตริงที่ตรงกับกฎมัลแวร์")
                    rec = meta.get("recommendation", "แยกไฟล์เพื่อตรวจสอบความปลอดภัยและหลีกเลี่ยงการรัน")
                    severity = meta.get("severity", "high" if "eicar" in rule_name.lower() or "ransom" in rule_name.lower() else "medium")

                    findings.append({
                        "filename": filename,
                        "path": str(file_path),
                        "threat_name": rule_name,
                        "level": severity,
                        "detail": desc,
                        "recommendation": rec,
                    })
            except (yara.Error, OSError, PermissionError):
                pass

        return findings

    def _run_scan_worker(self, mode: str, custom_path: Optional[str]) -> None:
        target_paths = self._get_target_paths(mode, custom_path)
        with self._lock:
            self.state["target"] = ", ".join(str(p) for p in target_paths)

        files_count = 0
        dirs_count = 0

        for base_path in target_paths:
            if self._stop_requested:
                break

            if base_path.is_file():
                files_count += 1
                with self._lock:
                    self.state["files_scanned"] = files_count
                    self.state["current_file"] = str(base_path)
                threats = self._scan_single_file(base_path)
                if threats:
                    with self._lock:
                        self.state["threats"].extend(threats)
                continue

            for root_str, dirs, files in os.walk(base_path, topdown=True, followlinks=False):
                if self._stop_requested:
                    break

                # Filter out system and excluded directories
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in EXCLUDED_DIR_NAMES
                    and not d.startswith("$")
                ]

                dirs_count += 1
                with self._lock:
                    self.state["directories_scanned"] = dirs_count

                for fname in files:
                    if self._stop_requested:
                        break

                    full_path = Path(root_str) / fname
                    files_count += 1

                    # Update current file in state periodically
                    if files_count % 5 == 0 or files_count < 20:
                        with self._lock:
                            self.state["files_scanned"] = files_count
                            self.state["current_file"] = str(full_path)

                    threats = self._scan_single_file(full_path)
                    if threats:
                        with self._lock:
                            self.state["threats"].extend(threats)

        with self._lock:
            if not self._stop_requested:
                self.state["status"] = "completed"
                self.state["current_file"] = "การสแกนเสร็จสมบูรณ์"
            self.state["files_scanned"] = files_count
            self.state["directories_scanned"] = dirs_count
            self.state["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if self.state["started_at"]:
                start_dt = datetime.datetime.fromisoformat(self.state["started_at"])
                self.state["elapsed_seconds"] = round((datetime.datetime.now(datetime.timezone.utc) - start_dt).total_seconds(), 1)
            self.is_scanning = False
