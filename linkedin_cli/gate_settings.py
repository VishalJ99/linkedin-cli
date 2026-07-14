"""Configuration for the Railway authentication feasibility gate."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from argon2 import extract_parameters
from argon2.exceptions import InvalidHashError

from .security import CookieCipher
from .security import SecurityConfigurationError


_DEPLOYMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_COMMIT_SHA_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "testserver"}


class GateSettingsError(ValueError):
    """Raised when required gate settings are absent or unsafe."""


@dataclass(frozen=True)
class GateSettings:
    """Validated runtime settings; secret values are never rendered."""

    database_path: Path
    access_password_hash: str
    app_session_secret: str
    cookie_encryption_key: str
    public_base_url: str
    app_user_id: str = "friend"
    secure_cookies: bool = True
    deployment_id: str = "local"
    commit_sha: str = "local"

    @classmethod
    def from_env(cls) -> "GateSettings":
        """Load and validate settings from sealed environment variables."""
        public_base_url = _required_env("PUBLIC_BASE_URL").rstrip("/")
        parsed = _validate_base_url(public_base_url)
        secure_default = parsed.scheme == "https"
        settings = cls(
            database_path=Path(os.getenv("DATABASE_PATH", "/app/data/linkedin_finder.sqlite3")),
            access_password_hash=_required_env("APP_ACCESS_PASSWORD_HASH"),
            app_session_secret=_required_env("APP_SESSION_SECRET"),
            cookie_encryption_key=_required_env("COOKIE_ENCRYPTION_KEY"),
            public_base_url=public_base_url,
            app_user_id=os.getenv("APP_USER_ID", "friend").strip() or "friend",
            secure_cookies=_env_bool("APP_SECURE_COOKIES", secure_default),
            deployment_id=(
                os.getenv("RAILWAY_DEPLOYMENT_ID") or os.getenv("APP_DEPLOYMENT_ID") or "local"
            ).strip(),
            commit_sha=(
                os.getenv("RAILWAY_GIT_COMMIT_SHA") or os.getenv("APP_COMMIT_SHA") or "local"
            )
            .strip()
            .lower(),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        """Reject unsafe or incomplete settings without including secrets in errors."""
        parsed = _validate_base_url(self.public_base_url)
        if not self.database_path.name:
            raise GateSettingsError("DATABASE_PATH must name a SQLite file.")
        if not self.access_password_hash.startswith("$argon2"):
            raise GateSettingsError("APP_ACCESS_PASSWORD_HASH must be an Argon2 encoded hash.")
        try:
            extract_parameters(self.access_password_hash)
        except InvalidHashError:
            raise GateSettingsError(
                "APP_ACCESS_PASSWORD_HASH must be a valid Argon2 encoded hash."
            ) from None
        if len(self.app_session_secret) < 32:
            raise GateSettingsError("APP_SESSION_SECRET must contain at least 32 characters.")
        if not self.cookie_encryption_key:
            raise GateSettingsError("COOKIE_ENCRYPTION_KEY is required.")
        try:
            CookieCipher.from_encoded_key(self.cookie_encryption_key)
        except SecurityConfigurationError:
            raise GateSettingsError("COOKIE_ENCRYPTION_KEY must encode exactly 32 bytes.") from None
        if not self.app_user_id:
            raise GateSettingsError("APP_USER_ID must not be empty.")
        if not _DEPLOYMENT_ID_PATTERN.fullmatch(self.deployment_id):
            raise GateSettingsError("Deployment ID contains unsupported characters.")
        if parsed.hostname not in _LOCAL_HOSTS and not _COMMIT_SHA_PATTERN.fullmatch(
            self.commit_sha
        ):
            raise GateSettingsError(
                "APP_COMMIT_SHA must be the full Git commit for a deployed gate."
            )
        if parsed.hostname not in _LOCAL_HOSTS and parsed.scheme != "https":
            raise GateSettingsError("PUBLIC_BASE_URL must use HTTPS outside local development.")
        if parsed.scheme == "https" and not self.secure_cookies:
            raise GateSettingsError("Secure cookies cannot be disabled for an HTTPS deployment.")

def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise GateSettingsError(f"{name} is required.")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise GateSettingsError(f"{name} must be true or false.")


def _validate_base_url(value: str):
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise GateSettingsError("PUBLIC_BASE_URL must be an absolute HTTP(S) origin.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise GateSettingsError("PUBLIC_BASE_URL must not contain credentials, query, or fragment.")
    if parsed.path not in {"", "/"}:
        raise GateSettingsError("PUBLIC_BASE_URL must be an origin without a path.")
    return parsed
