import os
from pathlib import Path
from uuid import uuid4

import psycopg

from vault.db import AdminDatabase
from vault.errors import safe_event
from vault.storage import EncryptedStorage


def purge_one(database, storage, document):
    request_id = uuid4()
    try:
        # Commit a state that blocks all new reads/restores.
        with database.transaction() as repository:
            reference = repository.begin_purge(document)
        if reference is None:
            return False
        if reference != storage.reference(document):
            raise ValueError("Invalid storage reference")
        path = storage.root / reference
        # Missing ciphertext is acceptable on a retry after a crash.
        # unlink removes a symlink itself rather than following it.
        path.unlink(missing_ok=True)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(storage.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        with database.transaction() as repository:
            completed = repository.finish_purge(document)
            if completed:
                repository.audit(
                    None,
                    document,
                    request_id,
                    "purge",
                    "ok",
                    "ADMIN_PURGE",
                )
        return completed
    except (psycopg.Error, OSError, ValueError):
        database.failure_audit(
            None,
            document,
            request_id,
            "purge",
            "PURGE_FAILED",
        )
        safe_event("PURGE_FAILED", request_id)
        return False


def main():
    database = AdminDatabase(os.environ["ADMIN_DATABASE_URL"])
    storage = EncryptedStorage(Path(os.environ["VAULT_ROOT"]))
    with database.transaction() as repository:
        candidates = repository.purge_candidates()
    completed = sum(
        purge_one(database, storage, row["id"])
        for row in candidates
    )
    # Counts only: no filenames, tokens, or key material.
    print({
        "examined": len(candidates),
        "purged": completed,
    })


if __name__ == "__main__":
    main()
