import asyncio
from datetime import datetime
from urllib.parse import quote
from uuid import UUID, uuid4

import psycopg
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException

from vault.auth import OIDCAuthenticator, RateLimiter
from vault.config import Settings
from vault.db import Database
from vault.encryption_service import MAX_FILE_BYTES
from vault.errors import HTTP_STATUS, VaultError, safe_event
from vault.kek_provider import KekProvider
from vault.key_manager import KeyManager
from vault.storage import EncryptedStorage
from vault.token_service import TokenService

bearer = HTTPBearer(auto_error=False)


def error_response(code, request_id, status=None):
    return JSONResponse(
        {"error": code, "request_id": str(request_id)},
        status_code=status or HTTP_STATUS.get(code, 500),
    )


class Guard:
    """Bound request bodies and concurrency before FastAPI buffers input."""

    def __init__(self, app, database, limiter):
        self.app = app
        self.database = database
        self.limiter = limiter
        self.active = 0
        self.max_active = 8

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid4()
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        started = False

        async def safe_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                headers.extend([
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-request-id", str(request_id).encode("ascii")),
                ])
                message = {**message, "headers": headers}
            await send(message)

        async def reject(code, status=None):
            response = error_response(code, request_id, status)
            await response(scope, receive, safe_send)

        client = scope.get("client")
        address = client[0] if client else "unknown"
        if not self.limiter.allow(("ip", address)):
            await reject("RATE_LIMITED")
            return
        if self.active >= self.max_active:
            await reject("BUSY")
            return
        self.active += 1
        try:
            limit = (
                MAX_FILE_BYTES
                if scope["method"] == "POST" and scope["path"] == "/documents"
                else 16 * 1024
            )
            headers = dict(scope["headers"])
            content_length = headers.get(b"content-length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError:
                    await reject("INVALID_REQUEST")
                    return
                if declared < 0:
                    await reject("INVALID_REQUEST")
                    return
                if declared > limit:
                    await reject("FILE_TOO_LARGE")
                    return
            chunks = []
            total = 0
            try:
                async with asyncio.timeout(30):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        if message["type"] != "http.request":
                            continue
                        chunk = message.get("body", b"")
                        total += len(chunk)
                        if total > limit:
                            await reject("FILE_TOO_LARGE")
                            return
                        chunks.append(chunk)
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                await reject("INVALID_REQUEST", 408)
                return
            body = b"".join(chunks)
            chunks.clear()
            delivered = False

            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {
                        "type": "http.request",
                        "body": body,
                        "more_body": False,
                    }
                return await receive()

            await self.app(scope, replay, safe_send)
        except Exception:
            # Catch unexpected defects at the boundary without logging
            # exception messages, headers, request bodies, or frame locals.
            safe_event("INTERNAL_ERROR", request_id)
            await run_in_threadpool(
                self.database.failure_audit,
                state.get("actor"),
                state.get("document"),
                request_id,
                state.get("operation", "access"),
                "INTERNAL_ERROR",
            )
            if not started:
                await reject("INTERNAL_ERROR")
        finally:
            self.active -= 1


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
        title="Dynamic Encryption Digital Vault",
        version="0.2.0",
        docs_url="/docs" if settings.docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs else None,
    )
    app.add_middleware(Guard, database=database, limiter=limiter)

    @app.exception_handler(VaultError)
    async def vault_error(request, error):
        return error_response(error.code, request.state.request_id)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        # Do not echo submitted inputs.
        return error_response("INVALID_REQUEST", request.state.request_id, 422)

    @app.exception_handler(HTTPException)
    async def http_error(request, error):
        return error_response(
            "INVALID_REQUEST", request.state.request_id, error.status_code
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
    def documents(request: Request, actor=Depends(current_user)):
        with database.transaction() as repository:
            rows = repository.list_documents(actor)
            repository.audit(
                actor, None, request.state.request_id,
                "access", "granted", "OK",
            )
        return rows

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
        token: str = Header(alias="X-Vault-Token"),
        actor=Depends(current_user),
    ):
        request.state.document = document
        request.state.operation = "decrypt"
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

    def owner_view(actor, document, request_id, view):
        result = None
        with database.transaction() as repository:
            row = repository.owner(document)
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
