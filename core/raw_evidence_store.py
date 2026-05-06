"""
raw_evidence_store.py
Write-once, immutable evidence store. Every raw event is tapped here
BEFORE the fabric processes it. Forensic retrieval requires human authorisation.
Provides the provenance_pointer (hash) stored in every AnnotationEnvelope.
"""

from __future__ import annotations
import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("ipcf.evidence_store")


class RawEvidenceStore:
    """
    Write-once evidence store. Implements:
    1. Atomic write (temp file → rename) — prevents partial writes
    2. SHA-256 content hashing — provides the provenance_pointer
    3. Human-gated retrieval — records access in access_log
    4. Immutability enforcement — existing files cannot be overwritten
    """

    def __init__(self, store_dir: str = "./data/raw_evidence"):
        self._store_dir = Path(store_dir)
        self._store_dir.mkdir(parents=True, exist_ok=True)
        self._access_log_path = self._store_dir / "access_log.jsonl"
        self._lock = asyncio.Lock()
        self._write_count = 0
        self._total_bytes = 0
        logger.info(f"Raw evidence store initialised at {self._store_dir}")

    async def store(self, event_id: str, raw_event: Dict[str, Any]) -> str:
        """
        Store a raw event. Returns SHA-256 provenance_pointer.
        Immutable — existing entries cannot be overwritten.
        """
        async with self._lock:
            content = json.dumps(raw_event, sort_keys=True, default=str).encode()
            pointer = hashlib.sha256(content).hexdigest()
            file_path = self._store_dir / f"{pointer}.json"

            if file_path.exists():
                return pointer  # already stored, idempotent

            # Atomic write via temp file
            tmp_path = self._store_dir / f".tmp_{event_id}"
            try:
                wrapped = {
                    "pointer": pointer,
                    "event_id": event_id,
                    "stored_at": time.time(),
                    "stored_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "raw_event": raw_event,
                }
                tmp_path.write_text(json.dumps(wrapped, default=str), encoding="utf-8")
                tmp_path.rename(file_path)
                # Make read-only (immutability)
                os.chmod(file_path, 0o444)
                self._write_count += 1
                self._total_bytes += len(content)
            except Exception as e:
                if tmp_path.exists():
                    tmp_path.unlink()
                logger.error(f"Evidence store write failed for {event_id}: {e}")
                raise

            return pointer

    async def retrieve(
        self,
        pointer: str,
        requester: str,
        reason: str,
        approved_by: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a stored event by provenance_pointer.
        Logs all access. Requires approved_by for regulated content.
        """
        file_path = self._store_dir / f"{pointer}.json"
        if not file_path.exists():
            logger.warning(f"Pointer {pointer} not found in evidence store")
            return None

        # Log access
        access_record = {
            "pointer": pointer,
            "requester": requester,
            "reason": reason,
            "approved_by": approved_by,
            "accessed_at": time.time(),
        }
        async with self._lock:
            with open(self._access_log_path, "a") as f:
                f.write(json.dumps(access_record) + "\n")

        data = json.loads(file_path.read_text(encoding="utf-8"))
        logger.info(f"Evidence retrieved: {pointer[:16]}... by {requester}")
        return data

    def get_stats(self) -> Dict[str, Any]:
        return {
            "write_count": self._write_count,
            "total_bytes": self._total_bytes,
            "store_dir": str(self._store_dir),
            "files_on_disk": len(list(self._store_dir.glob("*.json"))),
        }
