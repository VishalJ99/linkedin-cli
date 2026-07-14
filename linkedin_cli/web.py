"""Private FastAPI website for the Railway LinkedIn authentication gate."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from datetime import timezone
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from typing import Annotated
from typing import Any
from typing import Optional

from fastapi import Depends
from fastapi import FastAPI
from fastapi import Form
from fastapi import Header
from fastapi import HTTPException
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from .config import load_config
from .gate_service import CookieJarError
from .gate_service import GateService
from .gate_service import GateStoppedError
from .gate_service import GATE_EXTRACTOR_VERSION
from .gate_service import MAX_COOKIE_PAYLOAD_BYTES
from .gate_service import PairingError
from .gate_service import SessionUnavailableError
from .gate_service import SessionAlreadyConnectedError
from .gate_settings import GateSettings
from .security import APP_SESSION_MAX_AGE_SECONDS
from .security import AppSessionSigner
from .security import InvitePassword
from .security import LoginThrottle
from .security import SessionTokenError
from .storage import Database


SESSION_COOKIE = "linkedin_finder_session"
CSRF_COOKIE = "linkedin_finder_csrf"
SCHEMA_VERSION = "gate-2"
EXTRACTOR_VERSION = GATE_EXTRACTOR_VERSION
PROMPT_VERSION = "not-enabled"
_PACKAGE_DIR = Path(__file__).parent


class PairingCompleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cookies: list[dict[str, Any]] = Field(min_length=1, max_length=200)


def create_app(
    settings: Optional[GateSettings] = None,
    *,
    database: Optional[Database] = None,
    service: Optional[GateService] = None,
) -> FastAPI:
    """Build the one-worker feasibility service without resolving secrets at import."""
    resolved_settings = settings or GateSettings.from_env()
    resolved_settings.validate()
    resolved_database = database or Database(resolved_settings.database_path)
    resolved_service = service or GateService(
        resolved_settings,
        resolved_database,
        load_config(),
    )
    password = InvitePassword(resolved_settings.access_password_hash)
    signer = AppSessionSigner(resolved_settings.app_session_secret)
    login_throttle = LoginThrottle()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        resolved_database.initialize()
        resolved_database.ensure_user(resolved_settings.app_user_id)
        _write_reproduction(
            resolved_settings.database_path.parent,
            resolved_settings.deployment_id,
            resolved_settings.commit_sha,
        )
        yield

    app = FastAPI(
        title="LinkedIn Conversation Finder",
        version="0.1.0-gate",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.database = resolved_database
    app.state.gate_service = resolved_service
    templates = Jinja2Templates(directory=str(_PACKAGE_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(_PACKAGE_DIR / "static")), name="static")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[resolved_settings.extension_origin],
        allow_credentials=False,
        allow_methods=["POST"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        body_limit = _request_body_limit(request)
        response: Response
        if body_limit is not None:
            raw_length = request.headers.get("content-length")
            if raw_length is None:
                response = JSONResponse(
                    status_code=411,
                    content={"detail": "Content-Length is required."},
                )
            else:
                try:
                    content_length = int(raw_length)
                except ValueError:
                    content_length = -1
                if content_length < 0:
                    response = JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length."},
                    )
                elif content_length > body_limit:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Request body is too large."},
                    )
                else:
                    body = bytearray()
                    async for chunk in request.stream():
                        body.extend(chunk)
                        if len(body) > body_limit:
                            break
                    if len(body) > body_limit:
                        response = JSONResponse(
                            status_code=413,
                            content={"detail": "Request body is too large."},
                        )
                    else:
                        # Starlette's cached request replays this bounded body to
                        # downstream form/JSON parsing without another socket read.
                        request._body = bytes(body)
                        response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; connect-src 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def redacted_validation_error(_: Request, __: RequestValidationError):
        # FastAPI's default response includes rejected input. Cookie values must never echo.
        return JSONResponse(status_code=422, content={"detail": "Invalid request."})

    def authenticated_user(request: Request) -> str:
        token = request.cookies.get(SESSION_COOKIE, "")
        try:
            session = signer.verify(token)
        except SessionTokenError:
            raise HTTPException(status_code=401, detail="Authentication required.") from None
        if session.user_id != resolved_settings.app_user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        generation = resolved_database.get_session_generation(session.user_id)
        if not generation or not hmac.compare_digest(generation, session.session_generation):
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session.user_id

    def csrf_protected(
        request: Request,
        user_id: str = Depends(authenticated_user),
        x_csrf_token: Optional[str] = Header(default=None),
    ) -> str:
        _verify_csrf(request.cookies.get(CSRF_COOKIE), x_csrf_token)
        return user_id

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        ready = await run_in_threadpool(resolved_database.ready)
        code = 200 if ready else 503
        return JSONResponse(status_code=code, content={"status": "ready" if ready else "not-ready"})

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if _optional_user(request, signer, resolved_database) == resolved_settings.app_user_id:
            return RedirectResponse("/", status_code=303)
        csrf_token = _fresh_csrf_token()
        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"csrf_token": csrf_token, "error": None},
        )
        _set_csrf_cookie(response, csrf_token, resolved_settings.secure_cookies)
        return response

    @app.post("/login", response_class=HTMLResponse)
    async def login(
        request: Request,
        passcode: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()],
    ):
        _verify_csrf(request.cookies.get(CSRF_COOKIE), csrf_token)
        throttle_subject = _login_subject(request, resolved_settings.app_session_secret)
        retry_after = login_throttle.reserve(throttle_subject)
        if retry_after:
            rotated_csrf = _fresh_csrf_token()
            response = templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "csrf_token": rotated_csrf,
                    "error": "Too many attempts. Wait before trying again.",
                },
                status_code=429,
            )
            response.headers["Retry-After"] = str(retry_after)
            _set_csrf_cookie(response, rotated_csrf, resolved_settings.secure_cookies)
            return response
        accepted = len(passcode) <= 256 and await run_in_threadpool(password.verify, passcode)
        if not accepted:
            rotated_csrf = _fresh_csrf_token()
            response = templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"csrf_token": rotated_csrf, "error": "That passcode was not accepted."},
                status_code=401,
            )
            _set_csrf_cookie(response, rotated_csrf, resolved_settings.secure_cookies)
            return response

        await run_in_threadpool(
            resolved_database.ensure_user,
            resolved_settings.app_user_id,
        )
        session_generation = await run_in_threadpool(
            resolved_database.get_session_generation,
            resolved_settings.app_user_id,
        )
        if not session_generation:
            raise HTTPException(status_code=500, detail="Application session could not be created.")
        login_throttle.reset(throttle_subject)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            signer.issue(resolved_settings.app_user_id, session_generation),
            max_age=APP_SESSION_MAX_AGE_SECONDS,
            secure=resolved_settings.secure_cookies,
            httponly=True,
            samesite="lax",
            path="/",
        )
        rotated_csrf = _fresh_csrf_token()
        _set_csrf_cookie(response, rotated_csrf, resolved_settings.secure_cookies)
        return response

    @app.post("/logout")
    async def logout(
        request: Request,
        csrf_token: Annotated[str, Form()],
    ):
        authenticated_user(request)
        _verify_csrf(request.cookies.get(CSRF_COOKIE), csrf_token)
        await run_in_threadpool(
            resolved_database.rotate_session_generation,
            resolved_settings.app_user_id,
        )
        response = RedirectResponse("/login", status_code=303)
        _clear_auth_cookies(response, resolved_settings.secure_cookies)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        try:
            user_id = authenticated_user(request)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        gate_status = await run_in_threadpool(resolved_service.status, user_id)
        csrf_token = request.cookies.get(CSRF_COOKIE) or _fresh_csrf_token()
        response = templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "csrf_token": csrf_token,
                "extension_id": resolved_settings.extension_id,
                "gate_status": gate_status,
            },
        )
        if not request.cookies.get(CSRF_COOKIE):
            _set_csrf_cookie(response, csrf_token, resolved_settings.secure_cookies)
        return response

    @app.post("/api/pairings", status_code=201)
    async def create_pairing_api(
        user_id: str = Depends(csrf_protected),
    ) -> dict[str, Any]:
        try:
            pairing = await run_in_threadpool(resolved_service.create_pairing, user_id)
        except GateStoppedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except SessionAlreadyConnectedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {
            "pairing_id": pairing.id,
            "pairing_token": pairing.token,
            "expires_at": pairing.expires_at,
            "api_base": resolved_settings.public_base_url,
            "extension_id": resolved_settings.extension_id,
        }

    @app.get("/api/pairings/{pairing_id}")
    async def pairing_status_api(
        pairing_id: str,
        user_id: str = Depends(authenticated_user),
    ) -> dict[str, Any]:
        result = await run_in_threadpool(
            resolved_service.pairing_status,
            user_id,
            pairing_id,
        )
        if result is None:
            raise HTTPException(status_code=404, detail="Pairing not found.")
        return result

    @app.post("/api/pairings/{pairing_id}/complete")
    async def complete_pairing_api(
        pairing_id: str,
        body: PairingCompleteBody,
        request: Request,
        authorization: Optional[str] = Header(default=None),
    ) -> dict[str, Any]:
        if request.headers.get("origin") != resolved_settings.extension_origin:
            raise HTTPException(status_code=403, detail="Extension origin required.")
        raw_token = _bearer_token(authorization)
        try:
            return await run_in_threadpool(
                resolved_service.complete_pairing,
                pairing_id,
                raw_token,
                body.cookies,
            )
        except PairingError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from None
        except CookieJarError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        except GateStoppedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except SessionAlreadyConnectedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @app.get("/api/linkedin/status")
    async def linkedin_status_api(
        user_id: str = Depends(authenticated_user),
    ) -> dict[str, Any]:
        return await run_in_threadpool(resolved_service.status, user_id)

    @app.post("/api/linkedin/probe")
    async def linkedin_probe_api(
        user_id: str = Depends(csrf_protected),
    ) -> dict[str, Any]:
        try:
            return await run_in_threadpool(resolved_service.probe, user_id)
        except SessionUnavailableError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except GateStoppedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @app.post("/api/linkedin/disconnect")
    async def linkedin_disconnect_api(
        user_id: str = Depends(csrf_protected),
    ) -> dict[str, bool]:
        deleted = await run_in_threadpool(resolved_service.disconnect, user_id)
        return {"disconnected": deleted}

    @app.delete("/api/data")
    async def delete_data_api(
        user_id: str = Depends(csrf_protected),
    ) -> Response:
        await run_in_threadpool(resolved_service.delete_user_data, user_id)
        response = JSONResponse(content={"deleted": True})
        _clear_auth_cookies(response, resolved_settings.secure_cookies)
        return response

    return app


def _optional_user(
    request: Request,
    signer: AppSessionSigner,
    database: Database,
) -> Optional[str]:
    try:
        session = signer.verify(request.cookies.get(SESSION_COOKIE, ""))
    except SessionTokenError:
        return None
    generation = database.get_session_generation(session.user_id)
    if not generation or not hmac.compare_digest(generation, session.session_generation):
        return None
    return session.user_id


def _request_body_limit(request: Request) -> Optional[int]:
    if request.method == "POST" and request.url.path in {"/login", "/logout"}:
        return 4_096
    if (
        request.method == "POST"
        and request.url.path.startswith("/api/pairings/")
        and request.url.path.endswith("/complete")
    ):
        return MAX_COOKIE_PAYLOAD_BYTES + 8_192
    return None


def _login_subject(request: Request, secret: str) -> str:
    source = request.client.host if request.client is not None else "unknown"
    return hmac.new(secret.encode("utf-8"), source.encode("utf-8"), hashlib.sha256).hexdigest()


def _fresh_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _verify_csrf(cookie_token: Optional[str], presented_token: Optional[str]) -> None:
    if not cookie_token or not presented_token:
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    if not hmac.compare_digest(cookie_token, presented_token):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")


def _set_csrf_cookie(response: Response, token: str, secure: bool) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=APP_SESSION_MAX_AGE_SECONDS,
        secure=secure,
        httponly=False,
        samesite="lax",
        path="/",
    )


def _clear_auth_cookies(response: Response, secure: bool) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        secure=secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(
        CSRF_COOKIE,
        secure=secure,
        httponly=False,
        samesite="lax",
        path="/",
    )


def _bearer_token(value: Optional[str]) -> str:
    if not value or not value.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Pairing authorization required.")
    token = value[7:].strip()
    if not token or len(token) > 256:
        raise HTTPException(status_code=401, detail="Pairing authorization required.")
    return token


def _write_reproduction(output_dir: Path, deployment_id: str, commit_sha: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "commit_sha": commit_sha,
        "deployment_id": deployment_id,
        "extractor_version": EXTRACTOR_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limits": {"discovered": 500, "enriched": 80, "recommendations": 5},
        "prompt_version": PROMPT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "ticket": "PER-379",
    }
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path = output_dir / "reproduction.txt"
    temporary = output_dir / ".reproduction.txt.tmp"
    temporary.write_text(serialized, encoding="utf-8")
    temporary.replace(path)


def reproduction_fingerprint(path: Path) -> str:
    """Return a stable digest useful for smoke-test readback without exposing content."""
    return hashlib.sha256(path.read_bytes()).hexdigest()
