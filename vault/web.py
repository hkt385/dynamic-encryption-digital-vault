from datetime import datetime
from urllib.parse import quote
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException

# Reuse the existing bounded-body/security middleware.
from vault.api import Guard, error_response
from vault.auth import OIDCAuthenticator, RateLimiter
from vault.config import Settings
from vault.db import Database
from vault.errors import VaultError
from vault.kek_provider import KekProvider
from vault.key_manager import (
    KeyManager,
    USER_DOCUMENT_LIMIT,
    USER_QUOTA_BYTES,
)
from vault.storage import EncryptedStorage
from vault.token_service import TokenService

bearer = HTTPBearer(auto_error=False)


class GrantInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient_id: UUID
    expiry: datetime


def create_app(settings=None, keys=None):
    settings = settings or Settings.from_env()
    keys = keys or KekProvider.from_env()
    database = Database(settings.database_url)
    storage = EncryptedStorage(settings.storage_root)
    manager = KeyManager(database, storage, keys)
    tokens = TokenService(database)
    authenticator = OIDCAuthenticator(settings)
    limiter = RateLimiter()
    app = FastAPI(
        title="Dynamic Vault",
        docs_url="/docs" if settings.docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs else None,
    )
    app.add_middleware(
        Guard,
        database=database,
        limiter=limiter,
    )

    @app.exception_handler(VaultError)
    async def vault_error(request, error):
        return error_response(error.code, request.state.request_id)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        return error_response(
            "INVALID_REQUEST", request.state.request_id, 422
        )

    @app.exception_handler(HTTPException)
    async def http_error(request, error):
        return error_response(
            "INVALID_REQUEST",
            request.state.request_id,
            error.status_code,
        )

    def current_user(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ):
        request_id = request.state.request_id
        try:
            if credentials is None or credentials.scheme.lower() != "bearer":
                raise VaultError("AUTH_REQUIRED")
            issuer, subject = authenticator.verify(credentials.credentials)
        except VaultError as error:
            try:
                with database.transaction() as repository:
                    repository.audit(
                        None, None, request_id,
                        "access", "denied", error.code,
                    )
            except psycopg.Error:
                raise VaultError("DATABASE_UNAVAILABLE") from None
            raise
        try:
            with database.transaction() as repository:
                actor = repository.provision_user(issuer, subject)
            request.state.actor = actor
            if not limiter.allow(("user", str(actor))):
                with database.transaction() as repository:
                    repository.audit(
                        actor, None, request_id,
                        "access", "denied", "RATE_LIMITED",
                    )
                raise VaultError("RATE_LIMITED")
            return actor
        except psycopg.Error:
            raise VaultError("DATABASE_UNAVAILABLE") from None

    @app.get("/health")
    def health():
        return {"status": "alive"}

    @app.get("/ready")
    def ready():
        try:
            with database.transaction() as repository:
                repository.ready()
                repository.verify_keys(keys.fingerprints(), keys.active)
        except (psycopg.Error, VaultError):
            raise VaultError("DATABASE_UNAVAILABLE") from None
        return {"status": "ready"}

    @app.get("/me")
    def me(request: Request, actor=Depends(current_user)):
        with database.transaction() as repository:
            repository.audit(
                actor, None, request.state.request_id,
                "access", "granted", "OK",
            )
        return {"id": actor}

    @app.post("/documents", status_code=201)
    async def upload(
        request: Request,
        filename: str = Header(alias="X-Filename"),
        actor=Depends(current_user),
    ):
        if request.headers.get("content-type", "").split(";")[0] != (
            "application/octet-stream"
        ):
            raise VaultError("INVALID_REQUEST")
        request.state.operation = "encrypt"
        body = await request.body()
        document = await run_in_threadpool(
            manager.encrypt,
            actor,
            filename,
            body,
            request.state.request_id,
        )
        return {"document_id": document}

    @app.get("/documents")
    def documents(
        request: Request,
        trash: bool = Query(False),
        limit: int = Query(25, ge=1, le=100),
        offset: int = Query(0, ge=0),
        actor=Depends(current_user),
    ):
        with database.transaction() as repository:
            rows = repository.list_documents(
                actor, trash=trash, limit=limit, offset=offset
            )
            repository.audit(
                actor, None, request.state.request_id,
                "access", "granted", "OK",
            )
        return rows

    @app.get("/usage")
    def usage(request: Request, actor=Depends(current_user)):
        with database.transaction() as repository:
            row = repository.usage(actor)
            repository.audit(
                actor, None, request.state.request_id,
                "access", "granted", "OK",
            )
        return {
            "used_bytes": row["size"],
            "quota_bytes": USER_QUOTA_BYTES,
            "document_count": row["count"],
            "document_limit": USER_DOCUMENT_LIMIT,
        }

    @app.post("/documents/{document}/grants", status_code=201)
    def grant(
        document: UUID,
        body: GrantInput,
        request: Request,
        actor=Depends(current_user),
    ):
        request.state.document = document
        request.state.operation = "grant"
        result = tokens.grant(
            actor, document, body.recipient_id,
            body.expiry, request.state.request_id,
        )
        # Plaintext token appears only in this one response.
        return {
            "policy_id": result.policy_id,
            "token_id": result.token_id,
            "token": result.token,
            "notice": "Shown once. Store securely; revoke and reissue if lost.",
        }

    @app.post("/tokens/{token_id}/revoke", status_code=204)
    def revoke(token_id: UUID, request: Request, actor=Depends(current_user)):
        request.state.operation = "revoke"
        tokens.revoke(actor, token_id, request.state.request_id)
        return Response(status_code=204)

    @app.get("/documents/{document}/content")
    def download(
        document: UUID,
        request: Request,
        token: str | None = Header(default=None, alias="X-Vault-Token"),
        actor=Depends(current_user),
    ):
        request.state.document = document
        request.state.operation = "decrypt"
        # Absent header means "owner downloading their own document":
        # KeyManager.decrypt treats token=None as an owner-only path.
        result = manager.decrypt(
            actor, document, token, request.state.request_id
        )
        return Response(
            content=result.data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (
                    "attachment; filename=\"download\"; "
                    f"filename*=UTF-8''{quote(result.filename, safe='')}"
                ),
            },
        )

    @app.post("/documents/{document}/trash", status_code=204)
    def trash(document: UUID, request: Request, actor=Depends(current_user)):
        request.state.document = document
        request.state.operation = "trash"
        request_id = request.state.request_id
        try:
            with database.transaction() as repository:
                changed = repository.change_lifecycle(actor, document, "trash")
                repository.audit(
                    actor, document, request_id, "access",
                    "granted" if changed else "denied",
                    "OK" if changed else "ACCESS_DENIED",
                )
                repository.audit(
                    actor, document, request_id, "trash",
                    "ok" if changed else "denied",
                    "OK" if changed else "ACCESS_DENIED",
                )
        except psycopg.Error:
            database.failure_audit(
                actor, document, request_id, "trash", "DATABASE_UNAVAILABLE"
            )
            raise VaultError("DATABASE_UNAVAILABLE") from None
        if not changed:
            raise VaultError("ACCESS_DENIED")
        return Response(status_code=204)

    @app.post("/documents/{document}/restore", status_code=204)
    def restore(document: UUID, request: Request, actor=Depends(current_user)):
        request.state.document = document
        request.state.operation = "restore"
        request_id = request.state.request_id
        try:
            with database.transaction() as repository:
                changed = repository.change_lifecycle(actor, document, "restore")
                repository.audit(
                    actor, document, request_id, "access",
                    "granted" if changed else "denied",
                    "OK" if changed else "ACCESS_DENIED",
                )
                repository.audit(
                    actor, document, request_id, "restore",
                    "ok" if changed else "denied",
                    "OK" if changed else "ACCESS_DENIED",
                )
        except psycopg.Error:
            database.failure_audit(
                actor, document, request_id, "restore", "DATABASE_UNAVAILABLE"
            )
            raise VaultError("DATABASE_UNAVAILABLE") from None
        if not changed:
            raise VaultError("ACCESS_DENIED")
        return Response(status_code=204)

    def owner_view(actor, document, request_id, view):
        # Ownership is checked against key_metadata directly (not the
        # lifecycle-filtered `owner()` helper) so owners can still review
        # grants/audit history for a trashed document.
        result = None
        with database.transaction() as repository:
            row = repository.metadata(document)
            allowed = bool(row and row["owner_id"] == actor)
            repository.audit(
                actor, document, request_id, "access",
                "granted" if allowed else "denied",
                "OK" if allowed else "ACCESS_DENIED",
            )
            if allowed:
                result = (
                    repository.list_grants(document)
                    if view == "grants"
                    else repository.list_audit(document)
                )
        if result is None:
            raise VaultError("ACCESS_DENIED")
        return result

    @app.get("/documents/{document}/grants")
    def grants(document: UUID, request: Request, actor=Depends(current_user)):
        request.state.document = document
        return owner_view(actor, document, request.state.request_id, "grants")

    @app.get("/documents/{document}/audit")
    def audit(document: UUID, request: Request, actor=Depends(current_user)):
        request.state.document = document
        return owner_view(actor, document, request.state.request_id, "audit")

    return app
