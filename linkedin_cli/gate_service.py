"""Application service for the consented LinkedIn cookie replay gate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import math
import re
import threading
from typing import Any
from typing import Callable
from typing import Iterable

from .auth import auth_session_from_cookie_records
from .auth import collect_gate_diagnostics_for_session
from .config import AppConfig
from .gate_settings import GateSettings
from .security import CookieCipher
from .security import EncryptedCookiePayload
from .security import generate_pairing_token
from .security import hash_pairing_token
from .storage import Database


PAIRING_TTL = timedelta(minutes=10)
GATE_WINDOW = timedelta(hours=24)
MAX_COOKIE_COUNT = 200
MAX_COOKIE_VALUE_BYTES = 16_384
MAX_COOKIE_PAYLOAD_BYTES = 256_000
MAX_TRANSIENT_FAILURES = 3
REQUIRED_DEPLOYMENTS = 2
GATE_EXTRACTOR_VERSION = "feasibility-gate-1"
_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REQUIRED_COOKIE_NAMES = {"li_at", "JSESSIONID"}
_REJECTION_REASONS = {
    "authwall",
    "challenge",
    "checkpoint",
    "empty-redirect",
    "login",
    "invalid-payload",
    "missing-public-id",
    "profile-schema-drift",
    "rate-limit",
    "redirect",
    "schema-drift",
    "self-redirect-loop",
    "session-rejected",
}


class PairingError(ValueError):
    """Raised for invalid, expired, or already-consumed pairing handoffs."""


class CookieJarError(ValueError):
    """Raised when a connector payload is not a safe LinkedIn cookie jar."""


class SessionUnavailableError(RuntimeError):
    """Raised when no decryptable LinkedIn session is connected."""


class SessionAlreadyConnectedError(RuntimeError):
    """Raised when pairing would replace the session under active proof."""


class GateStoppedError(RuntimeError):
    """Raised when an irreversible gate outcome blocks further LinkedIn requests."""


class GateConfigurationError(ValueError):
    """Raised when deployment settings would invalidate the Railway-origin gate."""


@dataclass(frozen=True)
class Pairing:
    id: str
    token: str
    expires_at: str


class GateService:
    """Coordinates pairing, encrypted persistence, and bounded live probes."""

    def __init__(
        self,
        settings: GateSettings,
        database: Database,
        config: AppConfig,
        *,
        diagnostic_runner: Callable[[Any, AppConfig], dict[str, Any]] = (
            collect_gate_diagnostics_for_session
        ),
    ) -> None:
        self.settings = settings
        self.database = database
        self.config = config
        if config.runtime.proxy:
            raise GateConfigurationError(
                "LINKEDIN_PROXY must be unset for the Railway-origin feasibility gate."
            )
        self._cipher = CookieCipher.from_encoded_key(settings.cookie_encryption_key)
        self._diagnostic_runner = diagnostic_runner
        self._operation_lock = threading.RLock()

    def create_pairing(self, user_id: str) -> Pairing:
        with self._operation_lock:
            self._ensure_gate_open(user_id)
            if self.database.get_active_linkedin_session(user_id) is not None:
                raise SessionAlreadyConnectedError(
                    "Disconnect the current LinkedIn session before starting a new pairing."
                )
            raw_token = generate_pairing_token()
            expires_at = datetime.now(timezone.utc) + PAIRING_TTL
            pairing_id = self.database.create_pairing_token(
                user_id,
                hash_pairing_token(raw_token),
                expires_at,
            )
            return Pairing(
                id=pairing_id,
                token=raw_token,
                expires_at=_utc_iso(expires_at),
            )

    def pairing_status(self, user_id: str, pairing_id: str) -> dict[str, Any] | None:
        row = self.database.get_pairing_token(pairing_id, user_id)
        if row is None:
            return None
        now = datetime.now(timezone.utc)
        if row["consumed_at"]:
            state = "completed"
        elif _parse_utc(row["expires_at"]) <= now:
            state = "expired"
        else:
            state = "waiting"
        return {
            "id": row["id"],
            "state": state,
            "expires_at": row["expires_at"],
        }

    def complete_pairing(
        self,
        pairing_id: str,
        raw_token: str,
        cookies: Iterable[dict[str, Any]],
    ) -> dict[str, Any]:
        with self._operation_lock:
            self._ensure_gate_open()
            normalized = normalize_linkedin_cookies(cookies)
            user_id = self.database.consume_pairing_token(
                pairing_id,
                hash_pairing_token(raw_token),
                datetime.now(timezone.utc),
            )
            if user_id is None:
                raise PairingError("Pairing token is invalid, expired, or already used.")
            self._ensure_gate_open(user_id)
            if self.database.get_active_linkedin_session(user_id) is not None:
                raise SessionAlreadyConnectedError(
                    "Disconnect the current LinkedIn session before starting a new pairing."
                )

            aad = self._aad(user_id)
            envelope = self._cipher.encrypt(normalized, aad=aad)
            self.database.save_linkedin_session(
                user_id,
                envelope.ciphertext.encode("ascii"),
                envelope.nonce.encode("ascii"),
                aad.encode("utf-8"),
                [cookie["name"] for cookie in normalized],
                expires_at=_cookie_expiry(normalized),
            )
            return {
                "connected": True,
                "probe_pending": True,
            }

    def probe(self, user_id: str) -> dict[str, Any]:
        with self._operation_lock:
            self._ensure_gate_open(user_id)
            return self._probe_locked(user_id)

    def _probe_locked(self, user_id: str) -> dict[str, Any]:
        row = self.database.get_active_linkedin_session(user_id)
        if row is None:
            raise SessionUnavailableError("No active LinkedIn session is connected.")
        expected_aad = self._aad(user_id).encode("utf-8")
        if row["aad"] != expected_aad:
            raise SessionUnavailableError("Stored LinkedIn session could not be authenticated.")

        envelope = EncryptedCookiePayload(
            nonce=row["nonce"].decode("ascii"),
            ciphertext=row["ciphertext"].decode("ascii"),
        )
        cookies = self._cipher.decrypt(envelope, aad=row["aad"])
        session = auth_session_from_cookie_records(
            cookies,
            source="mac-connector",
            proxy=None,
        )
        try:
            diagnostics = self._diagnostic_runner(session, self.config)
        except Exception:
            # Live exception strings can include response fragments. Count the
            # failure, but persist only a stable, sanitized classification.
            diagnostics = {
                "ok": False,
                "public_id": "",
                "full_name": "",
                "validation": {
                    "ok": False,
                    "kind": "diagnostic-runner-error",
                    "status_code": None,
                },
                "probes": {},
            }
        status, kind = classify_diagnostics(diagnostics)
        detail = sanitized_diagnostics(diagnostics)
        if status == "rejected":
            self.database.stop_gate(kind)
        elif status == "error":
            self.database.record_transient_gate_failure(maximum=MAX_TRANSIENT_FAILURES)
        self.database.record_auth_probe(
            user_id,
            status,
            kind,
            linkedin_session_id=row["id"],
            deployment_id=self.settings.deployment_id,
            commit_sha=self.settings.commit_sha,
            extractor_version=GATE_EXTRACTOR_VERSION,
            public_id=str(diagnostics.get("public_id") or ""),
            full_name=str(diagnostics.get("full_name") or ""),
            detail=json.dumps(detail, sort_keys=True, separators=(",", ":")),
        )
        self.status(user_id)
        return {
            "status": status,
            "kind": kind,
            "public_id": str(diagnostics.get("public_id") or ""),
            "full_name": str(diagnostics.get("full_name") or ""),
            "checks": detail,
        }

    def status(self, user_id: str) -> dict[str, Any]:
        session = self.database.get_active_linkedin_session(user_id)
        probes = self.database.list_auth_probes(user_id)
        control = self.database.get_gate_control()
        successful = [
            probe
            for probe in probes
            if probe["status"] == "passed"
            and session is not None
            and probe["linkedin_session_id"] == session["id"]
            and probe["commit_sha"] == self.settings.commit_sha
            and probe["extractor_version"] == GATE_EXTRACTOR_VERSION
        ]
        deployments = {probe["deployment_id"] for probe in successful}

        if control["state"] != "open":
            gate_state = control["state"]
        elif session is None:
            gate_state = "awaiting_connection"
        elif len(successful) < 3:
            gate_state = "awaiting_probes"
        elif _probe_span(successful) < GATE_WINDOW:
            gate_state = "awaiting_24_hours"
        elif len(deployments) < REQUIRED_DEPLOYMENTS:
            gate_state = "awaiting_redeploy"
        else:
            gate_state = "passed"
            self.database.complete_gate()
            control = self.database.get_gate_control()

        return {
            "connected": session is not None,
            "gate_state": gate_state,
            "successful_probes": len(successful),
            "required_probes": 3,
            "required_window_hours": 24,
            "observed_deployments": len(deployments),
            "required_deployments": REQUIRED_DEPLOYMENTS,
            "commit_sha": self.settings.commit_sha,
            "extractor_version": GATE_EXTRACTOR_VERSION,
            "transient_failures": control["transient_failures"],
            "stop_reason": control["reason"]
            if control["state"] in {"rejected", "retry_exhausted"}
            else "",
            "completion_reason": control["reason"] if control["state"] == "passed" else "",
            "first_success_at": successful[0]["created_at"] if successful else None,
            "latest_success_at": successful[-1]["created_at"] if successful else None,
            "latest_probe": _public_probe(probes[-1]) if probes else None,
        }

    def disconnect(self, user_id: str) -> bool:
        with self._operation_lock:
            return self.database.delete_linkedin_session(user_id)

    def delete_user_data(self, user_id: str) -> bool:
        with self._operation_lock:
            return self.database.delete_user_data(user_id)

    def _ensure_gate_open(self, user_id: str | None = None) -> None:
        control = self.database.get_gate_control()
        if control["state"] == "passed":
            raise GateStoppedError(
                "The feasibility gate is complete; further LinkedIn requests are disabled."
            )
        if control["state"] == "rejected":
            raise GateStoppedError(
                "The feasibility gate is stopped after a terminal LinkedIn response."
            )
        if control["state"] == "retry_exhausted":
            raise GateStoppedError(
                "The feasibility gate is stopped after three transient failures."
            )
        if user_id is not None and self.status(user_id)["gate_state"] == "passed":
            raise GateStoppedError(
                "The feasibility gate is complete; further LinkedIn requests are disabled."
            )

    @staticmethod
    def _aad(user_id: str) -> str:
        return f"linkedin-session:v1:{user_id}"


def normalize_linkedin_cookies(
    cookie_records: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate and minimize a Chrome cookie jar without exposing values."""
    if isinstance(cookie_records, (str, bytes, dict)):
        raise CookieJarError("LinkedIn cookies must be provided as a list.")
    try:
        records = list(cookie_records)
    except TypeError:
        raise CookieJarError("LinkedIn cookies must be provided as a list.") from None
    if not records or len(records) > MAX_COOKIE_COUNT:
        raise CookieJarError("LinkedIn cookie count is outside the accepted range.")

    normalized: list[dict[str, Any]] = []
    identities = set()
    now_epoch = datetime.now(timezone.utc).timestamp()
    for record in records:
        if not isinstance(record, dict):
            raise CookieJarError("Every LinkedIn cookie must be an object.")
        name = record.get("name")
        value = record.get("value")
        domain = str(record.get("domain") or "").strip().lower()
        path = str(record.get("path") or "/").strip() or "/"
        if not isinstance(name, str) or not _COOKIE_NAME.fullmatch(name):
            raise CookieJarError("A LinkedIn cookie has an invalid name.")
        if (
            not isinstance(value, str)
            or not value
            or any(character in value for character in "\r\n\x00")
        ):
            raise CookieJarError("A LinkedIn cookie has an empty or invalid value.")
        if len(value.encode("utf-8")) > MAX_COOKIE_VALUE_BYTES:
            raise CookieJarError("A LinkedIn cookie value is too large.")
        if not _is_linkedin_domain(domain):
            raise CookieJarError("Only linkedin.com cookies are accepted.")
        if not path.startswith("/") or len(path) > 1024:
            raise CookieJarError("A LinkedIn cookie has an invalid path.")
        identity = (name, domain, path)
        if identity in identities:
            raise CookieJarError("The LinkedIn cookie jar contains a duplicate cookie.")
        identities.add(identity)

        secure = record.get("secure", True)
        http_only = record.get("httpOnly", False)
        if not isinstance(secure, bool) or not isinstance(http_only, bool):
            raise CookieJarError("A LinkedIn cookie has invalid security flags.")
        item: dict[str, Any] = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "secure": secure,
            "httpOnly": http_only,
        }
        expiration = record.get("expirationDate")
        if expiration is not None:
            if (
                isinstance(expiration, bool)
                or not isinstance(expiration, (int, float))
                or not math.isfinite(expiration)
            ):
                raise CookieJarError("A LinkedIn cookie has an invalid expiration.")
            if expiration <= now_epoch and name in _REQUIRED_COOKIE_NAMES:
                raise CookieJarError("A required LinkedIn cookie has expired.")
            item["expirationDate"] = float(expiration)
        normalized.append(item)

    present = {item["name"] for item in normalized if item["value"]}
    if not _REQUIRED_COOKIE_NAMES <= present:
        raise CookieJarError("LinkedIn session is missing required cookies.")
    encoded_size = len(
        json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    if encoded_size > MAX_COOKIE_PAYLOAD_BYTES:
        raise CookieJarError("LinkedIn cookie payload is too large.")
    return sorted(normalized, key=lambda item: (item["name"], item["domain"], item["path"]))


def classify_diagnostics(diagnostics: dict[str, Any]) -> tuple[str, str]:
    validation = diagnostics.get("validation") or {}
    probes = diagnostics.get("probes") or {}
    failures = [validation] + [item for item in probes.values() if isinstance(item, dict)]
    for item in failures:
        reason = str(item.get("reason") or item.get("kind") or "").lower()
        status_code = item.get("status_code")
        if reason in _REJECTION_REASONS:
            return "rejected", reason
        if isinstance(status_code, int) and status_code >= 400 and not 500 <= status_code < 600:
            return "rejected", f"http-{status_code}"
    profile_probe = probes.get("voyager_profile")
    if (
        diagnostics.get("ok")
        and diagnostics.get("public_id")
        and isinstance(profile_probe, dict)
        and profile_probe.get("ok")
    ):
        return "passed", "authenticated-profile"
    return "error", "probe-error"


def sanitized_diagnostics(diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Retain status evidence only; omit response bodies, headers, and cookie data."""
    validation = diagnostics.get("validation") or {}
    probes = diagnostics.get("probes") or {}
    return {
        "validation": _sanitized_check(validation),
        "probes": {
            str(name): _sanitized_check(result)
            for name, result in probes.items()
            if isinstance(result, dict)
        },
    }


def _sanitized_check(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(value.get("ok")),
        "kind": str(value.get("kind") or value.get("reason") or ""),
        "status_code": value.get("status_code")
        if isinstance(value.get("status_code"), int)
        else None,
    }


def _cookie_expiry(cookies: list[dict[str, Any]]) -> str | None:
    expirations = [
        float(cookie["expirationDate"])
        for cookie in cookies
        if cookie["name"] in _REQUIRED_COOKIE_NAMES and "expirationDate" in cookie
    ]
    if not expirations:
        return None
    return _utc_iso(datetime.fromtimestamp(min(expirations), tz=timezone.utc))


def _is_linkedin_domain(domain: str) -> bool:
    normalized = domain.lstrip(".")
    return normalized == "linkedin.com" or normalized.endswith(".linkedin.com")


def _probe_span(successful: list[dict[str, Any]]) -> timedelta:
    if len(successful) < 2:
        return timedelta(0)
    return _parse_utc(successful[-1]["created_at"]) - _parse_utc(successful[0]["created_at"])


def _public_probe(probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": probe["id"],
        "status": probe["status"],
        "kind": probe["kind"],
        "public_id": probe["public_id"],
        "full_name": probe["full_name"],
        "created_at": probe["created_at"],
    }


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
