from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import math
from pathlib import Path
import sqlite3
import threading
from typing import Any

import pytest

from linkedin_cli.config import AppConfig
from linkedin_cli.config import BrowserConfig
from linkedin_cli.config import FetchConfig
from linkedin_cli.config import FilterConfig
from linkedin_cli.config import RateLimitConfig
from linkedin_cli.config import RuntimeConfig
from linkedin_cli.gate_service import CookieJarError
from linkedin_cli.gate_service import GateConfigurationError
from linkedin_cli.gate_service import GateService
from linkedin_cli.gate_service import GateStoppedError
from linkedin_cli.gate_service import PairingError
from linkedin_cli.gate_service import SessionAlreadyConnectedError
from linkedin_cli.gate_service import classify_diagnostics
from linkedin_cli.gate_service import normalize_linkedin_cookies
from linkedin_cli.gate_settings import GateSettings
from linkedin_cli.security import hash_pairing_token
from linkedin_cli.storage import Database


SECRET_LI_AT = "AQED-DO-NOT-PERSIST-LI-AT"
SECRET_JSESSION = '"ajax:DO-NOT-PERSIST-JSESSION"'
FUTURE_EPOCH = 4_102_444_800.0
COMMIT_SHA = "a" * 40
EXTRACTOR_VERSION = "feasibility-gate-1"


def _settings(
    tmp_path: Path,
    *,
    deployment_id: str = "deployment-one",
    commit_sha: str = COMMIT_SHA,
) -> GateSettings:
    return GateSettings(
        database_path=tmp_path / "gate.sqlite3",
        access_password_hash="$argon2id$placeholder-for-service-tests",
        app_session_secret="s" * 32,
        cookie_encryption_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        public_base_url="https://finder.example",
        app_user_id="friend",
        secure_cookies=True,
        deployment_id=deployment_id,
        commit_sha=commit_sha,
    )


def _config(*, proxy: str | None = None) -> AppConfig:
    return AppConfig(
        fetch=FetchConfig(),
        filter=FilterConfig(),
        browser=BrowserConfig(),
        rate_limit=RateLimitConfig(),
        runtime=RuntimeConfig(proxy=proxy),
    )


def _cookies() -> list[dict[str, Any]]:
    return [
        {
            "name": "li_at",
            "value": SECRET_LI_AT,
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": True,
            "expirationDate": FUTURE_EPOCH,
            "sameSite": "no_restriction",
        },
        {
            "name": "JSESSIONID",
            "value": SECRET_JSESSION,
            "domain": ".www.linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "expirationDate": FUTURE_EPOCH,
        },
        {
            "name": "lang",
            "value": "v=2&lang=en-us",
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
        },
    ]


def _passed_diagnostics() -> dict[str, Any]:
    return {
        "ok": True,
        "public_id": "ada-friend",
        "full_name": "Ada Friend",
        "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
        "probes": {
            "voyager_me": {"ok": True, "kind": "ok", "status_code": 200},
            "voyager_feed": {"ok": True, "kind": "ok", "status_code": 200},
            "voyager_profile": {"ok": True, "kind": "ok", "status_code": 200},
        },
        "response_body": "must-not-be-persisted",
        "headers": {"cookie": SECRET_LI_AT},
    }


def _service(
    tmp_path: Path,
    *,
    diagnostic_runner=None,
    deployment_id: str = "deployment-one",
    commit_sha: str = COMMIT_SHA,
    proxy: str | None = None,
) -> tuple[GateService, Database]:
    database = Database(tmp_path / "gate.sqlite3")
    database.initialize()
    database.ensure_user("friend")
    runner = diagnostic_runner or (lambda _session, _config: _passed_diagnostics())
    return (
        GateService(
            _settings(
                tmp_path,
                deployment_id=deployment_id,
                commit_sha=commit_sha,
            ),
            database,
            _config(proxy=proxy),
            diagnostic_runner=runner,
        ),
        database,
    )


def test_normalize_linkedin_cookies_minimizes_and_sorts_without_mutating_input() -> None:
    cookies = _cookies()
    original = [dict(cookie) for cookie in cookies]

    normalized = normalize_linkedin_cookies(cookies)

    assert cookies == original
    assert [cookie["name"] for cookie in normalized] == ["JSESSIONID", "lang", "li_at"]
    assert normalized[0] == {
        "name": "JSESSIONID",
        "value": SECRET_JSESSION,
        "domain": ".www.linkedin.com",
        "path": "/",
        "secure": True,
        "httpOnly": False,
        "expirationDate": FUTURE_EPOCH,
    }
    assert "sameSite" not in normalized[-1]


@pytest.mark.parametrize(
    ("cookies", "message"),
    [
        ("li_at=secret", "provided as a list"),
        ({"li_at": "secret"}, "provided as a list"),
        ([], "count"),
        (["not-an-object"], "must be an object"),
        ([{"name": "bad name", "value": "x", "domain": ".linkedin.com"}], "name"),
        ([{"name": "li_at", "value": "", "domain": ".linkedin.com"}], "value"),
        ([{"name": "li_at", "value": "x", "domain": ".linkedin.com.evil"}], "linkedin.com"),
        ([{"name": "li_at", "value": "x", "domain": ".linkedin.com", "path": "bad"}], "path"),
    ],
)
def test_normalize_rejects_malformed_cookie_jars_without_echoing_values(
    cookies: Any,
    message: str,
) -> None:
    with pytest.raises(CookieJarError, match=message) as exc_info:
        normalize_linkedin_cookies(cookies)

    assert SECRET_LI_AT not in str(exc_info.value)
    assert SECRET_JSESSION not in str(exc_info.value)


def test_normalize_requires_both_session_cookies_and_rejects_duplicates() -> None:
    with pytest.raises(CookieJarError, match="missing required"):
        normalize_linkedin_cookies([_cookies()[0]])

    with pytest.raises(CookieJarError, match="duplicate"):
        normalize_linkedin_cookies([*_cookies(), dict(_cookies()[0])])


def test_normalize_rejects_expired_required_cookie() -> None:
    cookies = _cookies()
    cookies[0]["expirationDate"] = 1.0

    with pytest.raises(CookieJarError, match="expired"):
        normalize_linkedin_cookies(cookies)


@pytest.mark.parametrize("invalid_expiration", [True, "tomorrow", math.nan, math.inf])
def test_normalize_rejects_invalid_or_non_finite_expiration(
    invalid_expiration: object,
) -> None:
    cookies = _cookies()
    cookies[0]["expirationDate"] = invalid_expiration

    with pytest.raises(CookieJarError, match="expiration"):
        normalize_linkedin_cookies(cookies)


@pytest.mark.parametrize("field", ["secure", "httpOnly"])
def test_normalize_rejects_non_boolean_cookie_flags(field: str) -> None:
    cookies = _cookies()
    cookies[0][field] = "false"

    with pytest.raises(CookieJarError):
        normalize_linkedin_cookies(cookies)


@pytest.mark.parametrize("forbidden", ["line\nbreak", "carriage\rreturn", "nul\x00byte"])
def test_normalize_rejects_cookie_value_control_characters(forbidden: str) -> None:
    cookies = _cookies()
    cookies[0]["value"] = forbidden

    with pytest.raises(CookieJarError, match="value"):
        normalize_linkedin_cookies(cookies)


def test_complete_pairing_encrypts_at_rest_then_explicit_probe_uses_session(
    tmp_path: Path,
) -> None:
    captured: dict[str, Any] = {}

    def runner(session, config):
        captured["source"] = session.source
        captured["li_at"] = session.li_at
        captured["jsessionid"] = session.jsessionid
        captured["proxy"] = config.runtime.proxy
        return _passed_diagnostics()

    service, database = _service(tmp_path, diagnostic_runner=runner)
    pairing = service.create_pairing("friend")

    result = service.complete_pairing(pairing.id, pairing.token, _cookies())

    assert result["connected"] is True
    assert result == {"connected": True, "probe_pending": True}
    assert captured == {}
    assert database.list_auth_probes("friend") == []

    probe = service.probe("friend")

    assert probe == {
        "status": "passed",
        "kind": "authenticated-profile",
        "public_id": "ada-friend",
        "full_name": "Ada Friend",
        "checks": {
            "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
            "probes": {
                "voyager_me": {"ok": True, "kind": "ok", "status_code": 200},
                "voyager_feed": {"ok": True, "kind": "ok", "status_code": 200},
                "voyager_profile": {"ok": True, "kind": "ok", "status_code": 200},
            },
        },
    }
    assert captured == {
        "source": "mac-connector",
        "li_at": SECRET_LI_AT,
        "jsessionid": "ajax:DO-NOT-PERSIST-JSESSION",
        "proxy": None,
    }
    stored = database.get_active_linkedin_session("friend")
    assert stored is not None
    assert stored["cookie_names"] == ["JSESSIONID", "lang", "li_at"]
    assert SECRET_LI_AT.encode() not in stored["ciphertext"]
    assert SECRET_JSESSION.encode() not in stored["ciphertext"]
    assert service.pairing_status("friend", pairing.id)["state"] == "completed"
    probes = database.list_auth_probes("friend")
    assert len(probes) == 1
    assert probes[0]["status"] == "passed"
    assert probes[0]["linkedin_session_id"] == stored["id"]
    assert probes[0]["deployment_id"] == "deployment-one"
    assert probes[0]["commit_sha"] == COMMIT_SHA
    assert probes[0]["extractor_version"] == EXTRACTOR_VERSION
    assert SECRET_LI_AT not in probes[0]["detail"]
    assert "must-not-be-persisted" not in probes[0]["detail"]

    for sqlite_file in tmp_path.glob("gate.sqlite3*"):
        raw = sqlite_file.read_bytes()
        assert SECRET_LI_AT.encode() not in raw
        assert SECRET_JSESSION.encode() not in raw


def test_pairing_token_is_single_use_and_expired_tokens_fail_closed(tmp_path: Path) -> None:
    service, database = _service(tmp_path)
    pairing = service.create_pairing("friend")
    service.complete_pairing(pairing.id, pairing.token, _cookies())

    with pytest.raises(PairingError, match="invalid, expired, or already used"):
        service.complete_pairing(pairing.id, pairing.token, _cookies())

    expired_token = "expired-synthetic-token"
    expired_id = database.create_pairing_token(
        "friend",
        hash_pairing_token(expired_token),
        datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    assert service.pairing_status("friend", expired_id)["state"] == "expired"
    with pytest.raises(PairingError, match="invalid, expired, or already used"):
        service.complete_pairing(expired_id, expired_token, _cookies())


@pytest.mark.parametrize(
    ("diagnostics", "expected"),
    [
        (_passed_diagnostics(), ("passed", "authenticated-profile")),
        (
            {
                "ok": False,
                "validation": {"ok": False, "kind": "checkpoint", "status_code": 302},
                "probes": {},
            },
            ("rejected", "checkpoint"),
        ),
        (
            {
                "ok": False,
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {"feed": {"ok": False, "kind": "login", "status_code": 302}},
            },
            ("rejected", "login"),
        ),
        (
            {
                "ok": False,
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {"feed": {"ok": False, "kind": "rate-limit", "status_code": 429}},
            },
            ("rejected", "rate-limit"),
        ),
        (
            {
                "ok": False,
                "validation": {"ok": False, "kind": "transport-error"},
                "probes": {},
            },
            ("error", "probe-error"),
        ),
    ],
)
def test_diagnostic_classification(
    diagnostics: dict[str, Any],
    expected: tuple[str, str],
) -> None:
    assert classify_diagnostics(diagnostics) == expected


def _set_probe_times(database: Database, timestamps: dict[str, datetime]) -> None:
    with sqlite3.connect(database.path) as connection:
        for probe_id, timestamp in timestamps.items():
            connection.execute(
                "UPDATE auth_probes SET created_at = ? WHERE id = ?",
                (
                    timestamp.astimezone(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                    probe_id,
                ),
            )


def _record_probe(
    database: Database,
    linkedin_session_id: str,
    *,
    deployment_id: str = "deployment-one",
    commit_sha: str = COMMIT_SHA,
    extractor_version: str = EXTRACTOR_VERSION,
    status: str = "passed",
    kind: str = "authenticated-profile",
) -> str:
    return database.record_auth_probe(
        "friend",
        status,
        kind,
        linkedin_session_id=linkedin_session_id,
        deployment_id=deployment_id,
        commit_sha=commit_sha,
        extractor_version=extractor_version,
    )


def test_gate_requires_current_session_commit_extractor_two_deployments_and_24_hours(
    tmp_path: Path,
) -> None:
    service, database = _service(tmp_path)
    assert service.status("friend")["gate_state"] == "awaiting_connection"

    old_session_id = database.save_linkedin_session(
        "friend",
        b"opaque-ciphertext",
        b"opaque-nonce",
        b"linkedin-session:v1:friend",
        ["li_at", "JSESSIONID"],
    )
    for _ in range(3):
        _record_probe(database, old_session_id)

    current_session_id = database.save_linkedin_session(
        "friend",
        b"current-ciphertext",
        b"current-nonce",
        b"linkedin-session:v1:friend",
        ["li_at", "JSESSIONID"],
    )
    assert service.status("friend")["gate_state"] == "awaiting_probes"
    assert service.status("friend")["successful_probes"] == 0
    with pytest.raises(SessionAlreadyConnectedError, match="Disconnect"):
        service.create_pairing("friend")

    _record_probe(database, current_session_id, commit_sha="b" * 40)
    _record_probe(database, current_session_id, extractor_version="obsolete-extractor")
    assert service.status("friend")["successful_probes"] == 0

    current_probe_ids = [_record_probe(database, current_session_id) for _ in range(3)]
    now = datetime.now(timezone.utc)
    _set_probe_times(
        database,
        {
            current_probe_ids[0]: now - timedelta(hours=2),
            current_probe_ids[1]: now - timedelta(hours=1),
            current_probe_ids[2]: now,
        },
    )

    short_window = service.status("friend")
    assert short_window["successful_probes"] == 3
    assert short_window["gate_state"] == "awaiting_24_hours"

    _set_probe_times(
        database,
        {
            current_probe_ids[0]: now - timedelta(hours=24),
            current_probe_ids[1]: now - timedelta(hours=12),
            current_probe_ids[2]: now,
        },
    )
    one_deployment = service.status("friend")
    assert one_deployment["gate_state"] == "awaiting_redeploy"
    assert one_deployment["observed_deployments"] == 1

    _record_probe(database, current_session_id, deployment_id="deployment-two")
    passed = service.status("friend")
    assert passed["gate_state"] == "passed"
    assert passed["successful_probes"] == 4
    assert passed["required_probes"] == 3
    assert passed["required_window_hours"] == 24
    assert passed["observed_deployments"] == passed["required_deployments"] == 2
    assert passed["commit_sha"] == COMMIT_SHA
    assert passed["extractor_version"] == EXTRACTOR_VERSION
    assert passed["first_success_at"] < passed["latest_success_at"]
    assert passed["completion_reason"] == "three-probe-proof"
    assert database.get_gate_control()["state"] == "passed"
    with pytest.raises(GateStoppedError, match="complete"):
        service.probe("friend")
    with pytest.raises(GateStoppedError, match="complete"):
        service.create_pairing("friend")

    assert database.delete_user_data("friend") is True
    restarted = GateService(_settings(tmp_path), Database(database.path), _config())
    assert restarted.status("friend")["gate_state"] == "passed"
    with pytest.raises(GateStoppedError, match="complete"):
        restarted.create_pairing("friend")


def test_any_linkedin_rejection_creates_an_irreversible_gate_tombstone(tmp_path: Path) -> None:
    rejected = {
        "ok": False,
        "validation": {"ok": False, "kind": "checkpoint", "status_code": 302},
        "probes": {},
    }
    service, database = _service(
        tmp_path,
        diagnostic_runner=lambda _session, _config: rejected,
    )
    pairing = service.create_pairing("friend")

    stored = service.complete_pairing(pairing.id, pairing.token, _cookies())
    result = service.probe("friend")

    assert stored == {"connected": True, "probe_pending": True}
    assert result["status"] == "rejected"
    status = service.status("friend")
    assert status["gate_state"] == "rejected"
    assert status["latest_probe"]["status"] == "rejected"
    assert "detail" not in status["latest_probe"]

    assert database.delete_user_data("friend") is True
    restarted = GateService(
        _settings(tmp_path),
        Database(database.path),
        _config(),
        diagnostic_runner=lambda _session, _config: _passed_diagnostics(),
    )
    assert restarted.status("friend")["gate_state"] == "rejected"
    with pytest.raises(GateStoppedError, match="terminal LinkedIn response"):
        restarted.create_pairing("friend")


@pytest.mark.parametrize(
    ("diagnostics", "expected_kind"),
    [
        (
            {
                "ok": False,
                "public_id": "",
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {
                    "voyager_profile": {
                        "ok": False,
                        "kind": "missing-public-id",
                        "status_code": 200,
                    }
                },
            },
            "missing-public-id",
        ),
        (
            {
                "ok": False,
                "public_id": "ada-friend",
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {
                    "voyager_profile": {
                        "ok": False,
                        "reason": "profile-schema-drift",
                        "status_code": 200,
                    }
                },
            },
            "profile-schema-drift",
        ),
        (
            {
                "ok": False,
                "public_id": "ada-friend",
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {
                    "voyager_profile": {
                        "ok": False,
                        "reason": "authwall",
                        "status_code": 200,
                    }
                },
            },
            "authwall",
        ),
        (
            {
                "ok": False,
                "public_id": "ada-friend",
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {
                    "voyager_profile": {
                        "ok": False,
                        "reason": "http-error",
                        "status_code": 404,
                    }
                },
            },
            "http-404",
        ),
        (
            {
                "ok": False,
                "public_id": "ada-friend",
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {
                    "voyager_profile": {
                        "ok": False,
                        "reason": "http-error",
                        "status_code": 410,
                    }
                },
            },
            "http-410",
        ),
        (
            {
                "ok": False,
                "public_id": "ada-friend",
                "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
                "probes": {
                    "voyager_profile": {
                        "ok": False,
                        "reason": "http-error",
                        "status_code": 999,
                    }
                },
            },
            "http-999",
        ),
    ],
)
def test_schema_auth_content_and_non_retryable_4xx_stop_after_one_network_call(
    tmp_path: Path,
    diagnostics: dict[str, Any],
    expected_kind: str,
) -> None:
    calls = 0

    def runner(_session, _config):
        nonlocal calls
        calls += 1
        return diagnostics

    service, database = _service(tmp_path, diagnostic_runner=runner)
    pairing = service.create_pairing("friend")
    service.complete_pairing(pairing.id, pairing.token, _cookies())

    first = service.probe("friend")

    assert first["status"] == "rejected"
    assert first["kind"] == expected_kind
    with pytest.raises(GateStoppedError, match="terminal LinkedIn response"):
        service.probe("friend")
    assert calls == 1
    assert database.get_gate_control()["reason"] == expected_kind


def test_three_total_transient_failures_exhaust_gate_even_with_success_between(
    tmp_path: Path,
) -> None:
    transient_error = {
        "ok": False,
        "validation": {"ok": False, "kind": "transport-error"},
        "probes": {},
    }
    diagnostics = [
        transient_error,
        _passed_diagnostics(),
        transient_error,
        transient_error,
    ]

    def runner(_session, _config):
        return diagnostics.pop(0)

    service, database = _service(tmp_path, diagnostic_runner=runner)
    pairing = service.create_pairing("friend")
    service.complete_pairing(pairing.id, pairing.token, _cookies())
    first = service.probe("friend")
    success = service.probe("friend")
    second = service.probe("friend")
    third = service.probe("friend")

    assert [first["status"], success["status"], second["status"], third["status"]] == [
        "error",
        "passed",
        "error",
        "error",
    ]
    exhausted = service.status("friend")
    assert exhausted["gate_state"] == "retry_exhausted"
    assert exhausted["transient_failures"] == 3
    assert [probe["status"] for probe in database.list_auth_probes("friend")] == [
        "error",
        "passed",
        "error",
        "error",
    ]
    with pytest.raises(GateStoppedError, match="three transient failures"):
        service.probe("friend")
    assert database.get_gate_control()["transient_failures"] == 3


def test_gate_rejects_proxy_configuration_without_echoing_credentials(tmp_path: Path) -> None:
    proxy = "https://proxy-user:PROXY-SECRET@proxy.example:8443"

    with pytest.raises(GateConfigurationError, match="must be unset") as exc_info:
        _service(tmp_path, proxy=proxy)

    assert "PROXY-SECRET" not in str(exc_info.value)


def test_concurrent_probes_serialize_and_second_stops_before_network_after_rejection(
    tmp_path: Path,
) -> None:
    rejection_started = threading.Event()
    release_rejection = threading.Event()
    calls_lock = threading.Lock()
    calls = 0

    def runner(_session, _config):
        nonlocal calls
        with calls_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            return _passed_diagnostics()
        if call_number == 2:
            rejection_started.set()
            if not release_rejection.wait(timeout=5):
                raise AssertionError("Timed out waiting to release synthetic rejection.")
            return {
                "ok": False,
                "validation": {"ok": False, "kind": "checkpoint", "status_code": 302},
                "probes": {},
            }
        raise AssertionError("A stopped concurrent probe reached the diagnostic runner.")

    service, _database = _service(tmp_path, diagnostic_runner=runner)
    pairing = service.create_pairing("friend")
    assert service.complete_pairing(pairing.id, pairing.token, _cookies())["connected"] is True
    assert service.probe("friend")["status"] == "passed"

    second_attempted = threading.Event()

    def second_probe():
        second_attempted.set()
        return service.probe("friend")

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(service.probe, "friend")
        assert rejection_started.wait(timeout=2)
        second_future = executor.submit(second_probe)
        try:
            assert second_attempted.wait(timeout=2)
            assert second_future.done() is False
        finally:
            release_rejection.set()

        assert first_future.result(timeout=2)["status"] == "rejected"
        with pytest.raises(GateStoppedError, match="terminal LinkedIn response"):
            second_future.result(timeout=2)

    assert calls == 2
