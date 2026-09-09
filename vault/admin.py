import argparse
import os
import re
import sys
import time
from pathlib import Path
from uuid import uuid4

from vault import encryption_service as crypto
from vault.db import AdminDatabase
from vault.errors import VaultError
from vault.kek_provider import KekProvider, create_keyring_key
from vault.storage import EncryptedStorage

VAULT_FILE = re.compile(r"^[0-9a-f]{32}\.vault$")


def register_keys(database, keys):
    with database.transaction() as repository:
        repository.register_keys(keys.fingerprints())


def activate_key(database, keys):
    with database.transaction() as repository:
        repository.register_keys(keys.fingerprints())
        repository.activate(keys.active)


def rewrap_document(database, keys, document):
    request_id = uuid4()
    with database.transaction() as repository:
        row = repository.lock_metadata(document)
        if row is None or row["kek_version"] == keys.active:
            return False
        dek = crypto.unwrap_dek(
            bytes(row["wrapped_dek"]),
            keys.get_key(row["kek_version"]),
            crypto.key_aad(
                document, row["owner_id"], row["key_id"], row["kek_version"]
            ),
        )
        # Reservation commits independently before cryptographic use.
        nonce = database.reserve_nonce(keys.active)
        wrapped = crypto.wrap_dek(
            dek,
            keys.get_key(keys.active),
            nonce,
            crypto.key_aad(
                document, row["owner_id"], row["key_id"], keys.active
            ),
        )
        del dek
        repository.rewrap(row, wrapped, keys.active)
        repository.audit(
            None, document, request_id, "rewrap", "ok", "ADMIN_REWRAP"
        )
    return True


def reconcile(database, storage, quarantine=False):
    with database.transaction() as repository:
        rows = repository.storage_inventory()
    references = {row["storage_ref"] for row in rows}
    missing = sum(
        not (storage.root / reference).is_file()
        for reference in references
    )
    cutoff = time.time() - 3600
    orphans = []
    for path in storage.root.iterdir():
        if (
            VAULT_FILE.fullmatch(path.name)
            and not path.is_symlink()
            and path.is_file()
            and path.name not in references
            and path.stat().st_mtime < cutoff
        ):
            orphans.append(path)
    if quarantine:
        destination = storage.root / ".quarantine"
        destination.mkdir(mode=0o700, exist_ok=True)
        if destination.is_symlink():
            raise VaultError("INVALID_STORAGE")
        for path in orphans:
            # Unique destination; no automatic deletion.
            target = destination / f"{uuid4().hex}-{path.name}"
            os.replace(path, target)
    return {"missing": missing, "old_orphans": len(orphans)}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("new-key")
    new.add_argument("version")
    commands.add_parser("register-keys")
    commands.add_parser("activate-key")
    commands.add_parser("rewrap")
    scan = commands.add_parser("reconcile")
    scan.add_argument("--quarantine", action="store_true")
    scan.add_argument("--maintenance-ack", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "new-key":
            create_keyring_key(args.version)
            print("Key created in OS keyring; key value was not displayed.")
            return
        database = AdminDatabase(os.environ["ADMIN_DATABASE_URL"])
        if args.command == "reconcile":
            if args.quarantine and not args.maintenance_ack:
                raise VaultError("MAINTENANCE_REQUIRED")
            storage = EncryptedStorage(Path(os.environ["VAULT_ROOT"]))
            result = reconcile(database, storage, args.quarantine)
            print(result)
            return
        keys = KekProvider.from_env()
        if args.command == "register-keys":
            register_keys(database, keys)
            print("KEK fingerprints registered.")
        elif args.command == "activate-key":
            activate_key(database, keys)
            print("Active write KEK updated.")
        elif args.command == "rewrap":
            with database.transaction() as repository:
                documents = repository.documents_to_rewrap(keys.active)
            count = 0
            for row in documents:
                count += rewrap_document(database, keys, row["document_id"])
            print(f"Rewrapped documents: {count}")
    except Exception:
        # Administrative CLI also avoids printing potentially sensitive
        # exception messages and local variables.
        print("Maintenance command failed. Check configuration and audit records.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
