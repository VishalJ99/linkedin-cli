from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

from argon2 import PasswordHasher
import pytest

from linkedin_cli.gate_settings import GateSettings
from linkedin_cli.gate_settings import GateSettingsError


COMMIT_SHA = "c" * 40


def _password_hash() -> str:
    return PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1).hash("friend-passcode")


def _cookie_key() -> str:
    return base64.urlsafe_b64encode(b"k" * 32).decode("ascii")


def _settings(tmp_path: Path, **overrides: object) -> GateSettings:
    values: dict[str, object] = {
        "database_path": tmp_path / "gate.sqlite3",
        "access_password_hash": _password_hash(),
        "app_session_secret": "s" * 32,
        "cookie_encryption_key": _cookie_key(),
        "public_base_url": "https://finder.example",
        "app_user_id": "friend",
        "secure_cookies": True,
        "commit_sha": COMMIT_SHA,
    }
    values.update(overrides)
    return GateSettings(**values)  # type: ignore[arg-type]


def test_from_env_loads_and_normalizes_all_gate_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "finder.sqlite3"))
    monkeypatch.setenv("APP_ACCESS_PASSWORD_HASH", _password_hash())
    monkeypatch.setenv("APP_SESSION_SECRET", " session-secret-with-more-than-32-characters ")
    monkeypatch.setenv("COOKIE_ENCRYPTION_KEY", _cookie_key())
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://finder.example/")
    monkeypatch.setenv("APP_USER_ID", " invited-friend ")
    monkeypatch.setenv("APP_COMMIT_SHA", COMMIT_SHA.upper())
    monkeypatch.setenv("APP_DEPLOYMENT_ID", "deploy-1")

    settings = GateSettings.from_env()

    assert settings.database_path == tmp_path / "finder.sqlite3"
    assert settings.public_base_url == "https://finder.example"
    assert settings.app_user_id == "invited-friend"
    assert settings.secure_cookies is True
    assert settings.commit_sha == COMMIT_SHA
    assert settings.deployment_id == "deploy-1"


def test_local_http_defaults_to_non_secure_cookies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "finder.sqlite3"))
    monkeypatch.setenv("APP_ACCESS_PASSWORD_HASH", _password_hash())
    monkeypatch.setenv("APP_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("COOKIE_ENCRYPTION_KEY", _cookie_key())
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.delenv("APP_COMMIT_SHA", raising=False)
    monkeypatch.delenv("APP_SECURE_COOKIES", raising=False)

    settings = GateSettings.from_env()

    assert settings.secure_cookies is False


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("APP_ACCESS_PASSWORD_HASH", "", "APP_ACCESS_PASSWORD_HASH is required"),
        ("APP_SESSION_SECRET", "", "APP_SESSION_SECRET is required"),
        ("COOKIE_ENCRYPTION_KEY", "", "COOKIE_ENCRYPTION_KEY is required"),
        ("PUBLIC_BASE_URL", "", "PUBLIC_BASE_URL is required"),
    ],
)
def test_from_env_rejects_missing_required_values_without_echoing_other_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    value: str,
    message: str,
) -> None:
    session_secret = "DO-NOT-ECHO-session-secret-which-is-long-enough"
    cookie_key = _cookie_key()
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "finder.sqlite3"))
    monkeypatch.setenv("APP_ACCESS_PASSWORD_HASH", _password_hash())
    monkeypatch.setenv("APP_SESSION_SECRET", session_secret)
    monkeypatch.setenv("COOKIE_ENCRYPTION_KEY", cookie_key)
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://finder.example")
    monkeypatch.setenv("APP_COMMIT_SHA", COMMIT_SHA)
    monkeypatch.setenv(name, value)

    with pytest.raises(GateSettingsError, match=message) as exc_info:
        GateSettings.from_env()

    assert session_secret not in str(exc_info.value)
    assert cookie_key not in str(exc_info.value)


@pytest.mark.parametrize(
    ("base_url", "secure_cookies"),
    [
        ("finder.example", True),
        ("ftp://finder.example", True),
        ("https://user:pass@finder.example", True),
        ("https://finder.example/path", True),
        ("https://finder.example?secret=query", True),
        ("https://finder.example#fragment", True),
        ("http://finder.example", False),
        ("https://finder.example", False),
    ],
)
def test_validate_rejects_unsafe_public_origins(
    tmp_path: Path,
    base_url: str,
    secure_cookies: bool,
) -> None:
    settings = _settings(
        tmp_path,
        public_base_url=base_url,
        secure_cookies=secure_cookies,
    )

    with pytest.raises(GateSettingsError):
        settings.validate()


def test_validate_rejects_short_session_secret_and_non_argon_password_hash(
    tmp_path: Path,
) -> None:
    with pytest.raises(GateSettingsError, match="32 characters"):
        replace(_settings(tmp_path), app_session_secret="short").validate()

    with pytest.raises(GateSettingsError, match="Argon2"):
        replace(_settings(tmp_path), access_password_hash="sha256:not-argon").validate()


@pytest.mark.parametrize("commit_sha", ["", "unknown", "a" * 39, "g" * 40])
def test_deployed_gate_requires_full_git_commit(tmp_path: Path, commit_sha: str) -> None:
    with pytest.raises(GateSettingsError, match="APP_COMMIT_SHA"):
        _settings(tmp_path, commit_sha=commit_sha).validate()


@pytest.mark.parametrize(
    "invalid_key",
    [
        "not-base64!",
        base64.urlsafe_b64encode(b"too-short").decode("ascii"),
        base64.urlsafe_b64encode(b"x" * 31).decode("ascii"),
        base64.urlsafe_b64encode(b"x" * 33).decode("ascii"),
    ],
)
def test_validate_rejects_cookie_keys_that_are_not_base64_aes_256_keys(
    tmp_path: Path,
    invalid_key: str,
) -> None:
    with pytest.raises(GateSettingsError, match="COOKIE_ENCRYPTION_KEY") as exc_info:
        _settings(tmp_path, cookie_encryption_key=invalid_key).validate()

    assert invalid_key not in str(exc_info.value)


@pytest.mark.parametrize("raw", ["maybe", "2", "enabled", "truthy"])
def test_from_env_rejects_ambiguous_secure_cookie_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: str,
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "finder.sqlite3"))
    monkeypatch.setenv("APP_ACCESS_PASSWORD_HASH", _password_hash())
    monkeypatch.setenv("APP_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("COOKIE_ENCRYPTION_KEY", _cookie_key())
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("APP_SECURE_COOKIES", raw)

    with pytest.raises(GateSettingsError, match="must be true or false"):
        GateSettings.from_env()
