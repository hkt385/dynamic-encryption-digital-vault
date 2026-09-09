import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from vault.api import create_app
from vault.encryption_service import MAX_FILE_BYTES

pytestmark = pytest.mark.integration


def auth(token):
    return {"Authorization": "Bearer " + token}


def test_authenticated_api_round_trip(environment, api_settings, oidc_server):
    _, issue = oidc_server
    app = create_app(api_settings, environment.keys)
    with TestClient(app) as client:
        owner_token = issue("owner-api")
        recipient_token = issue("recipient-api")
        stranger_token = issue("stranger-api")
        recipient = client.get("/me", headers=auth(recipient_token)).json()["id"]
        uploaded = client.post(
            "/documents",
            headers={
                **auth(owner_token),
                "Content-Type": "application/octet-stream",
                "X-Filename": "example.txt",
            },
            content=b"API round trip",
        )
        assert uploaded.status_code == 201
        document = uploaded.json()["document_id"]
        granted = client.post(
            f"/documents/{document}/grants",
            headers=auth(owner_token),
            json={
                "recipient_id": recipient,
                "expiry": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(),
            },
        )
        assert granted.status_code == 201
        assert granted.headers["cache-control"] == "no-store"
        grant = granted.json()
        denied = client.get(
            f"/documents/{document}/content",
            headers={
                **auth(stranger_token),
                "X-Vault-Token": grant["token"],
            },
        )
        assert denied.status_code == 403
        downloaded = client.get(
            f"/documents/{document}/content",
            headers={
                **auth(recipient_token),
                "X-Vault-Token": grant["token"],
            },
        )
        assert downloaded.status_code == 200
        assert downloaded.content == b"API round trip"
        assert downloaded.headers["x-content-type-options"] == "nosniff"
        assert downloaded.headers["content-disposition"].startswith("attachment;")
        revoked = client.post(
            f"/tokens/{grant['token_id']}/revoke",
            headers=auth(owner_token),
        )
        assert revoked.status_code == 204
        denied = client.get(
            f"/documents/{document}/content",
            headers={
                **auth(recipient_token),
                "X-Vault-Token": grant["token"],
            },
        )
        assert denied.status_code == 403


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "wrong-api"},
        {"iss": "https://wrong-issuer.example"},
        {"scope": "other"},
        {"exp": 1},
    ],
)
def test_invalid_identity_tokens(environment, api_settings, oidc_server, overrides):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        response = client.get("/me", headers=auth(issue("user", **overrides)))
        assert response.status_code == 401


def test_missing_auth_and_oversized_body(environment, api_settings, oidc_server):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        assert client.get("/me").status_code == 401
        response = client.post(
            "/documents",
            headers={
                **auth(issue("owner")),
                "Content-Type": "application/octet-stream",
                "X-Filename": "large.bin",
            },
            content=b"x" * (MAX_FILE_BYTES + 1),
        )
        assert response.status_code == 413


def test_future_identity_token_rejected(environment, api_settings, oidc_server):
    _, issue = oidc_server
    with TestClient(create_app(api_settings, environment.keys)) as client:
        response = client.get(
            "/me",
            headers=auth(issue("user", iat=int(time.time()) + 3600)),
        )
        assert response.status_code == 401
