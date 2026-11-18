"""Audit log: a hash-chained table in <vault>/metadata/vault.db.

Each row stores SHA-256(previous row's hash + this row's content), so changing, inserting or
removing a row in the middle breaks the chain from that row on, and verify() reports it.

Limits (stated in docs/DEVELOPER_INSTRUCTIONS.md): the chain is not keyed. Someone who can write
vault.db can recompute every hash after an edit, or cut rows off the end, without detection. It
shows accidental damage and casual edits; it is not proof against a determined local attacker.

Never pass plaintext, keys, passwords or file contents to append().
"""
import hashlib
import json
from datetime import datetime, timezone

from services.storage_service import VaultDb

GENESIS = "0" * 64
OK, FAILED, DENIED = "OK", "FAILED", "DENIED"


def _row_hash(prev_hash: str, ts: str, action: str, file_id: str, level: str, result: str, detail: str) -> str:
    content = json.dumps([ts, action, file_id, level, result, detail], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((prev_hash + content).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, db: VaultDb):
        self.db = db

    def append(self, action: str, result: str = OK, file_id: str = "", level: str = "", detail: str = "") -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        with self.db as conn:
            last = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            conn.execute("INSERT INTO audit_log (ts, action, file_id, level, result, detail, prev_hash, hash) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (ts, action, file_id, level, result, detail, prev,
                          _row_hash(prev, ts, action, file_id, level, result, detail)))

    def entries(self) -> list[dict]:
        with self.db as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]

    def verify(self) -> tuple[bool, int, int | None]:
        """Returns (chain intact, number of rows, id of the first bad row or None)."""
        prev, rows = GENESIS, self.entries()
        for r in rows:
            expected = _row_hash(prev, r["ts"], r["action"], r["file_id"], r["level"], r["result"], r["detail"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return False, len(rows), r["id"]
            prev = r["hash"]
        return True, len(rows), None
