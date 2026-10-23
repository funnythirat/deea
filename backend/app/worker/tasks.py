import logging
from datetime import datetime, timezone
from pathlib import Path

from app.config import QUARANTINE_DIR
from app.database import SessionLocal
from app.models import ScanOutbox, VirusScan
from app.scanner import ScannerUnavailableError, scan_file
from app.worker.celery_app import celery_app
from sqlalchemy import and_, or_, select


logger = logging.getLogger(__name__)


@celery_app.task(name="virus_scanner.dispatch_outbox")
def dispatch_pending_scans() -> int:
    dispatched = 0
    with SessionLocal() as db:
        retry_before = datetime.now(timezone.utc).timestamp() - 60
        pending = db.scalars(
            select(ScanOutbox)
            .join(VirusScan, VirusScan.id == ScanOutbox.scan_id)
            .where(
                VirusScan.status == "queued",
                or_(
                    ScanOutbox.status == "pending",
                    and_(
                        ScanOutbox.status == "dispatched",
                        ScanOutbox.dispatched_at.is_not(None),
                        ScanOutbox.dispatched_at
                        <= datetime.fromtimestamp(retry_before, timezone.utc),
                    ),
                ),
            )
            .order_by(ScanOutbox.created_at)
            .limit(100)
            .with_for_update(skip_locked=True)
        ).all()
        for message in pending:
            try:
                if message.task_name != "virus_scanner.scan_file":
                    logger.error("Refusing unknown outbox task %s", message.task_name)
                    message.status = "failed"
                    continue
                celery_app.send_task(
                    message.task_name,
                    args=[message.scan_id],
                    task_id=message.scan_id,
                )
            except Exception:
                logger.exception("Could not dispatch scan %s; it will be retried", message.scan_id)
                continue
            message.status = "dispatched"
            message.dispatched_at = datetime.now(timezone.utc)
            dispatched += 1
        db.commit()
    return dispatched


@celery_app.task(name="virus_scanner.scan_file", bind=True, max_retries=2)
def scan_virus_file(self, scan_id: str) -> None:
    redelivered = bool((self.request.delivery_info or {}).get("redelivered"))
    retry_count = self.request.retries
    with SessionLocal() as db:
        scan = (
            db.query(VirusScan)
            .filter(VirusScan.id == scan_id)
            .with_for_update()
            .one_or_none()
        )
        if scan is None:
            logger.error("Scan record %s is missing", scan_id)
            return
        if scan.status in {"completed", "failed"} or (
            scan.status == "running" and not redelivered and retry_count == 0
        ):
            logger.info("Ignoring duplicate scan task %s with status %s", scan_id, scan.status)
            return
        scan.status = "running"
        db.commit()
        path = Path(scan.file_path)
        mode = scan.mode

    cleanup_file = True
    try:
        result = scan_file(path, mode)
        with SessionLocal() as db:
            scan = db.get(VirusScan, scan_id)
            if scan is None:
                logger.error("Scan record %s disappeared before result save", scan_id)
                return
            scan.result = result
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    except ScannerUnavailableError as error:
        if retry_count < self.max_retries:
            cleanup_file = False
            countdown = min(30, 5 * (2**retry_count))
            logger.warning(
                "Scanner unavailable for %s; retry %s/%s in %s seconds",
                scan_id,
                retry_count + 1,
                self.max_retries,
                countdown,
            )
            raise self.retry(exc=error, countdown=countdown)
        logger.exception("Virus scan task exhausted retries for %s", scan_id)
        with SessionLocal() as db:
            scan = db.get(VirusScan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.error_code = "scanner_failed"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
    except Exception:
        logger.exception("Virus scan task failed for %s", scan_id)
        with SessionLocal() as db:
            scan = db.get(VirusScan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.error_code = "scanner_failed"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
    finally:
        if cleanup_file:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Could not remove quarantined upload for scan %s", scan_id)


STALE_RUNNING_SECONDS = 6 * 60 * 60
STALE_QUEUED_SECONDS = 24 * 60 * 60
ORPHAN_FILE_SECONDS = 60 * 60


@celery_app.task(name="virus_scanner.reap_stale_scans")
def reap_stale_scans() -> int:
    now = datetime.now(timezone.utc)
    running_cutoff = datetime.fromtimestamp(now.timestamp() - STALE_RUNNING_SECONDS, timezone.utc)
    queued_cutoff = datetime.fromtimestamp(now.timestamp() - STALE_QUEUED_SECONDS, timezone.utc)
    reaped = 0
    with SessionLocal() as db:
        stale = db.scalars(
            select(VirusScan)
            .where(
                or_(
                    and_(VirusScan.status == "running", VirusScan.created_at <= running_cutoff),
                    and_(VirusScan.status == "queued", VirusScan.created_at <= queued_cutoff),
                )
            )
            .limit(100)
            .with_for_update(skip_locked=True)
        ).all()
        for scan in stale:
            scan.status = "failed"
            scan.error_code = "scan_timeout"
            scan.completed_at = now
            try:
                Path(scan.file_path).unlink(missing_ok=True)
            except OSError:
                logger.exception("Could not remove quarantined upload for stale scan %s", scan.id)
            reaped += 1
        db.commit()

        if QUARANTINE_DIR.is_dir():
            active_ids = set(
                db.scalars(
                    select(VirusScan.id).where(VirusScan.status.in_(("queued", "running")))
                ).all()
            )
            file_cutoff = now.timestamp() - ORPHAN_FILE_SECONDS
            for path in QUARANTINE_DIR.iterdir():
                try:
                    if (
                        path.is_file()
                        and path.name not in active_ids
                        and path.stat().st_mtime < file_cutoff
                    ):
                        path.unlink()
                        logger.warning("Removed orphaned quarantine file %s", path.name)
                except OSError:
                    logger.exception("Could not remove orphaned quarantine file %s", path.name)
    if reaped:
        logger.warning("Marked %s stale scans as failed", reaped)
    return reaped
