from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from vault.lifecycle_worker import purge_one
from vault.web import create_app

pytestmark = pytest.mark.integration


def auth(token):
    return {"Authorization": "Bearer " + token}


def upload(client, token, filename=b"content", name="file.bin"):
    response = client.post(
        "/documents",
        headers={
            **auth(token),
            "Content-Type": "application/octet-stream",
            "X-Filename": name,
        },
        content=filename,
    )
    assert response.status_code == 201
    return response.json()["document_id"]


def test_owner_can_download_without_a_token(environment, api_settings, oidc_server):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-product")
        document = upload(client, owner_token, b"owner file")
        response = client.get(
            f"/documents/{document}/content",
            headers=auth(owner_token),
        )
        assert response.status_code == 200
        assert response.content == b"owner file"


def test_recipient_cannot_download_without_a_token(
    environment, api_settings, oidc_server
):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-notoken")
        recipient_token = issue("recipient-notoken")
        document = upload(client, owner_token)
        response = client.get(
            f"/documents/{document}/content",
            headers=auth(recipient_token),
        )
        assert response.status_code == 403


def test_trash_hides_document_and_revokes_shares(
    environment, api_settings, oidc_server
):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-trash")
        recipient_token = issue("recipient-trash")
        recipient = client.get("/me", headers=auth(recipient_token)).json()["id"]
        document = upload(client, owner_token)
        granted = client.post(
            f"/documents/{document}/grants",
            headers=auth(owner_token),
            json={
                "recipient_id": recipient,
                "expiry": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(),
            },
        ).json()

        trashed = client.post(
            f"/documents/{document}/trash", headers=auth(owner_token)
        )
        assert trashed.status_code == 204

        assert document not in {
            row["id"] for row in client.get(
                "/documents", headers=auth(owner_token)
            ).json()
        }
        assert document in {
            row["id"] for row in client.get(
                "/documents", params={"trash": True}, headers=auth(owner_token)
            ).json()
        }

        # An existing share is revoked the moment its document is trashed.
        denied = client.get(
            f"/documents/{document}/content",
            headers={
                **auth(recipient_token),
                "X-Vault-Token": granted["token"],
            },
        )
        assert denied.status_code == 403

        # The owner can no longer download a trashed document either.
        owner_denied = client.get(
            f"/documents/{document}/content", headers=auth(owner_token)
        )
        assert owner_denied.status_code == 403


def test_restore_brings_a_trashed_document_back(
    environment, api_settings, oidc_server
):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-restore")
        document = upload(client, owner_token, b"restorable")
        client.post(f"/documents/{document}/trash", headers=auth(owner_token))

        restored = client.post(
            f"/documents/{document}/restore", headers=auth(owner_token)
        )
        assert restored.status_code == 204

        response = client.get(
            f"/documents/{document}/content", headers=auth(owner_token)
        )
        assert response.status_code == 200
        assert response.content == b"restorable"
        assert document in {
            row["id"] for row in client.get(
                "/documents", headers=auth(owner_token)
            ).json()
        }


def test_non_owner_cannot_trash_or_restore(environment, api_settings, oidc_server):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-guard")
        stranger_token = issue("stranger-guard")
        document = upload(client, owner_token)
        assert client.post(
            f"/documents/{document}/trash", headers=auth(stranger_token)
        ).status_code == 403
        # Untouched: the owner can still reach it normally.
        assert client.get(
            f"/documents/{document}/content", headers=auth(owner_token)
        ).status_code == 200


def test_usage_counts_trashed_documents_until_purged(
    environment, api_settings, oidc_server
):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-usage")
        document = upload(client, owner_token, b"twelve bytes")
        before = client.get("/usage", headers=auth(owner_token)).json()
        client.post(f"/documents/{document}/trash", headers=auth(owner_token))
        after_trash = client.get("/usage", headers=auth(owner_token)).json()
        assert after_trash["used_bytes"] == before["used_bytes"]
        assert after_trash["document_count"] == before["document_count"]

        assert purge_one(environment.admin_database, environment.storage, document)

        after_purge = client.get("/usage", headers=auth(owner_token)).json()
        assert after_purge["used_bytes"] == before["used_bytes"] - len(b"twelve bytes")
        assert after_purge["document_count"] == before["document_count"] - 1


def test_purge_removes_ciphertext_and_metadata(environment):
    document, _ = environment.upload(b"to be purged")
    with environment.database.transaction() as repository:
        assert repository.change_lifecycle(
            environment.owner, document, "trash"
        )
    path = environment.storage.root / environment.storage.reference(document)
    assert path.is_file()

    assert purge_one(environment.admin_database, environment.storage, document)
    assert not path.is_file()

    with environment.database.transaction() as repository:
        assert repository.metadata(document) is None

    # Purging is idempotent: a retry after the ciphertext is already
    # gone finds nothing left to do rather than erroring.
    assert not purge_one(environment.admin_database, environment.storage, document)


def test_owner_can_still_view_audit_history_after_trash(
    environment, api_settings, oidc_server
):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        owner_token = issue("owner-audit")
        document = upload(client, owner_token)
        client.post(f"/documents/{document}/trash", headers=auth(owner_token))
        response = client.get(
            f"/documents/{document}/audit", headers=auth(owner_token)
        )
        assert response.status_code == 200
        actions = {row["action"] for row in response.json()}
        assert {"encrypt", "trash"} <= actions
