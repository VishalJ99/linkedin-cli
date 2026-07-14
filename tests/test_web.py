from __future__ import annotations

import base64
from dataclasses import dataclass
from io import BytesIO
import json
from pathlib import Path
import re
from typing import Any
from zipfile import ZipFile

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
import pytest

from linkedin_cli.config import AppConfig
from linkedin_cli.config import BrowserConfig
from linkedin_cli.config import FetchConfig
from linkedin_cli.config import FilterConfig
from linkedin_cli.config import RateLimitConfig
from linkedin_cli.config import RuntimeConfig
from linkedin_cli.gate_service import GateService
from linkedin_cli.gate_service import MAX_COOKIE_PAYLOAD_BYTES
from linkedin_cli.gate_settings import GateSettings
from linkedin_cli.mac_connector import CONNECTOR_FILENAME
from linkedin_cli.storage import Database
from linkedin_cli.web import CSRF_COOKIE
from linkedin_cli.web import SESSION_COOKIE
from linkedin_cli.web import create_app
COMMIT_SHA = "c" * 40
SECRET_LI_AT = "AQED-WEB-COOKIE-MUST-STAY-SECRET"
SECRET_JSESSION = '"ajax:WEB-COOKIE-MUST-STAY-SECRET"'


def _config() -> AppConfig:
    return AppConfig(
        fetch=FetchConfig(),
        filter=FilterConfig(),
        browser=BrowserConfig(),
        rate_limit=RateLimitConfig(),
        runtime=RuntimeConfig(),
    )


def _passed_diagnostics() -> dict[str, Any]:
    return {
        "ok": True,
        "public_id": "ada-friend",
        "full_name": "Ada Friend",
        "validation": {"ok": True, "kind": "profile-read", "status_code": 200},
        "probes": {
            "voyager_me": {"ok": True, "kind": "ok", "status_code": 200},
            "voyager_feed": {"ok": True, "kind": "ok", "status_code": 200},
            "voyager_profile": {"ok": True, "kind": "profile-read", "status_code": 200},
        },
    }


def _cookies() -> list[dict[str, Any]]:
    return [
        {
            "name": "li_at",
            "value": SECRET_LI_AT,
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": True,
        },
        {
            "name": "JSESSIONID",
            "value": SECRET_JSESSION,
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        },
    ]


@dataclass
class WebHarness:
    client: TestClient
    database: Database
    settings: GateSettings


@pytest.fixture
def web_harness(tmp_path: Path):
    database = Database(tmp_path / "data" / "linkedin_finder.sqlite3")
    settings = GateSettings(
        database_path=database.path,
        access_password_hash=PasswordHasher(
            time_cost=1,
            memory_cost=1024,
            parallelism=1,
        ).hash("friend-passcode"),
        app_session_secret="s" * 32,
        cookie_encryption_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        public_base_url="https://finder.example",
        app_user_id="friend",
        secure_cookies=True,
        deployment_id="deploy-web-1",
        commit_sha=COMMIT_SHA,
    )
    service = GateService(
        settings,
        database,
        _config(),
        diagnostic_runner=lambda _session, _config: _passed_diagnostics(),
    )
    app = create_app(settings, database=database, service=service)
    with TestClient(app, base_url="https://finder.example") as client:
        yield WebHarness(client=client, database=database, settings=settings)


def _login(client: TestClient) -> str:
    login_page = client.get("/login")
    assert login_page.status_code == 200
    csrf_token = client.cookies.get(CSRF_COOKIE)
    assert csrf_token
    response = client.post(
        "/login",
        data={"passcode": "friend-passcode", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    rotated_csrf = client.cookies.get(CSRF_COOKIE)
    assert rotated_csrf and rotated_csrf != csrf_token
    assert client.cookies.get(SESSION_COOKIE)
    return rotated_csrf


def _create_pairing(client: TestClient, csrf_token: str) -> dict[str, Any]:
    response = _download_connector(client, csrf_token)
    assert response.status_code == 200
    return _connector_config(response)


def _complete_pairing(client: TestClient, pairing: dict[str, Any]):
    return client.post(
        f"/api/pairings/{pairing['pairing_id']}/complete",
        headers={
            "Authorization": f"Bearer {pairing['pairing_token']}",
            "X-Connector-Commit": pairing["connector_commit"],
        },
        json={"cookies": _cookies()},
    )


def _download_connector(client: TestClient, csrf_token: str):
    return client.post(
        "/api/connectors/macos",
        headers={"X-CSRF-Token": csrf_token},
    )


def _connector_config(response) -> dict[str, str]:
    with ZipFile(BytesIO(response.content)) as archive:
        source = archive.read(CONNECTOR_FILENAME).decode("utf-8")
    matched = re.search(r"^CONNECTOR_CONFIG = (\{.*\})$", source, re.MULTILINE)
    assert matched is not None
    return json.loads(matched.group(1))


def test_login_issues_seven_day_secure_httponly_lax_session(web_harness: WebHarness) -> None:
    client = web_harness.client
    csrf_token = client.get("/login").cookies.get(CSRF_COOKIE)
    assert csrf_token

    response = client.post(
        "/login",
        data={"passcode": "friend-passcode", "csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    set_cookie_headers = response.headers.get_list("set-cookie")
    session_header = next(
        value for value in set_cookie_headers if value.startswith(f"{SESSION_COOKIE}=")
    ).lower()
    csrf_header = next(
        value for value in set_cookie_headers if value.startswith(f"{CSRF_COOKIE}=")
    ).lower()
    assert "max-age=604800" in session_header
    assert "secure" in session_header
    assert "httponly" in session_header
    assert "samesite=lax" in session_header
    assert "secure" in csrf_header
    assert "httponly" not in csrf_header
    assert "samesite=lax" in csrf_header
    assert response.headers["location"] == "/"


def test_login_rejects_wrong_passcode_without_echoing_it(web_harness: WebHarness) -> None:
    client = web_harness.client
    csrf_token = client.get("/login").cookies.get(CSRF_COOKIE)
    wrong_passcode = "WRONG-PASSCODE-MUST-NOT-ECHO"

    response = client.post(
        "/login",
        data={"passcode": wrong_passcode, "csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 401
    assert wrong_passcode not in response.text
    assert SESSION_COOKIE not in client.cookies
    assert "not accepted" in response.text


def test_authenticated_writes_require_matching_double_submit_csrf(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    csrf_token = _login(client)

    assert client.post("/api/connectors/macos").status_code == 403
    assert (
        client.post(
            "/api/connectors/macos",
            headers={"X-CSRF-Token": "wrong-token"},
        ).status_code
        == 403
    )
    assert _download_connector(client, csrf_token).status_code == 200

    unauthenticated = TestClient(client.app, base_url="https://finder.example")
    assert unauthenticated.get("/api/linkedin/status").status_code == 401


def test_connector_completion_requires_exact_commit_and_bearer_then_is_single_use(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    csrf_token = _login(client)
    pairing = _create_pairing(client, csrf_token)
    endpoint = f"/api/pairings/{pairing['pairing_id']}/complete"

    wrong_commit = client.post(
        endpoint,
        headers={
            "Authorization": f"Bearer {pairing['pairing_token']}",
            "X-Connector-Commit": "d" * 40,
        },
        json={"cookies": _cookies()},
    )
    assert wrong_commit.status_code == 409

    missing_bearer = client.post(
        endpoint,
        headers={"X-Connector-Commit": pairing["connector_commit"]},
        json={"cookies": _cookies()},
    )
    assert missing_bearer.status_code == 401

    wrong_bearer = client.post(
        endpoint,
        headers={
            "X-Connector-Commit": pairing["connector_commit"],
            "Authorization": "Bearer wrong-token",
        },
        json={"cookies": _cookies()},
    )
    assert wrong_bearer.status_code == 401

    completed = _complete_pairing(client, pairing)
    assert completed.status_code == 200
    assert completed.json()["connected"] is True
    assert completed.json()["probe_pending"] is True
    first_probe = client.post(
        "/api/linkedin/probe",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert first_probe.status_code == 200
    assert first_probe.json()["public_id"] == "ada-friend"
    assert pairing["api_base"] == "https://finder.example"
    replacement = client.post(
        "/api/connectors/macos",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert replacement.status_code == 409
    assert "Disconnect" in replacement.json()["detail"]
    assert "Session connected" in client.get("/").text

    reused = _complete_pairing(client, pairing)
    assert reused.status_code == 401
    pairing_status = client.get(f"/api/pairings/{pairing['pairing_id']}")
    assert pairing_status.json()["state"] == "completed"


def test_mac_connector_download_is_authenticated_csrf_protected_and_token_bound(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client

    assert client.post("/api/connectors/macos").status_code == 401
    csrf_token = _login(client)
    assert client.post("/api/connectors/macos").status_code == 403

    response = _download_connector(client, csrf_token)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["content-disposition"] == (
        'attachment; filename="LinkedIn-Connector.zip"'
    )
    pairing_id = response.headers["x-pairing-id"]
    assert pairing_id
    assert "pairing_token" not in response.headers
    config = _connector_config(response)
    assert config == {
        "api_base": "https://finder.example",
        "connector_commit": COMMIT_SHA,
        "pairing_id": pairing_id,
        "pairing_token": config["pairing_token"],
    }
    assert len(config["pairing_token"]) >= 32
    assert client.get(f"/api/pairings/{pairing_id}").json()["state"] == "waiting"
    assert (
        client.post("/api/pairings", headers={"X-CSRF-Token": csrf_token}).status_code
        == 404
    )


def test_new_connector_download_expires_the_older_unused_package(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    csrf_token = _login(client)
    first = _connector_config(_download_connector(client, csrf_token))
    second = _connector_config(_download_connector(client, csrf_token))

    assert first["pairing_id"] != second["pairing_id"]
    assert client.get(f"/api/pairings/{first['pairing_id']}").json()["state"] == "expired"
    assert _complete_pairing(client, first).status_code == 401
    assert _complete_pairing(client, second).status_code == 200


def test_mac_connector_completion_rejects_browser_origins_and_is_single_use(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    response = _download_connector(client, _login(client))
    config = _connector_config(response)
    endpoint = f"/api/pairings/{config['pairing_id']}/complete"
    headers = {
        "Authorization": f"Bearer {config['pairing_token']}",
        "X-Connector-Commit": config["connector_commit"],
    }

    browser_request = client.post(
        endpoint,
        headers={**headers, "Origin": "https://finder.example"},
        json={"cookies": _cookies()},
    )
    assert browser_request.status_code == 403

    completed = client.post(endpoint, headers=headers, json={"cookies": _cookies()})
    assert completed.status_code == 200
    assert completed.json() == {"connected": True, "probe_pending": True}
    assert SECRET_LI_AT not in completed.text
    assert SECRET_JSESSION not in completed.text

    reused = client.post(endpoint, headers=headers, json={"cookies": _cookies()})
    assert reused.status_code == 401


def test_dashboard_offers_mac_download_without_extension_bootstrap(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    _login(client)

    dashboard = client.get("/")

    assert "Download Mac connector" in dashboard.text
    assert "temporary Chrome profile" in dashboard.text
    assert "Chrome extension" not in dashboard.text
    assert "data-extension-id" not in dashboard.text
    javascript = client.get("/static/app.js").text
    assert "chrome.runtime" not in javascript
    assert "PAIR_LINKEDIN" not in javascript


def test_malformed_cookie_payload_is_redacted_and_does_not_consume_pairing(
    web_harness: WebHarness,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = web_harness.client
    pairing = _create_pairing(client, _login(client))
    endpoint = f"/api/pairings/{pairing['pairing_id']}/complete"
    headers = {
        "Authorization": f"Bearer {pairing['pairing_token']}",
        "X-Connector-Commit": pairing["connector_commit"],
    }
    leaked_value = "COOKIE-VALUE-MUST-NEVER-ECHO"

    validation_error = client.post(
        endpoint,
        headers=headers,
        json={"cookies": leaked_value, "extra": leaked_value},
    )
    assert validation_error.status_code == 422
    assert validation_error.json() == {"detail": "Invalid request."}
    assert leaked_value not in validation_error.text

    invalid_cookie = client.post(
        endpoint,
        headers=headers,
        json={
            "cookies": [
                {
                    "name": "li_at",
                    "value": {"secret": leaked_value},
                    "domain": ".linkedin.com",
                }
            ]
        },
    )
    assert invalid_cookie.status_code == 400
    assert leaked_value not in invalid_cookie.text
    assert leaked_value not in caplog.text

    completed = _complete_pairing(client, pairing)
    assert completed.status_code == 200
    assert completed.json()["probe_pending"] is True


def test_health_readiness_security_headers_and_reproduction_file(
    web_harness: WebHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = web_harness.client
    health = client.get("/healthz")
    ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}
    for response in (health, ready):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    reproduction = web_harness.database.path.parent / "reproduction.txt"
    assert reproduction.exists()
    reproduction_text = reproduction.read_text(encoding="utf-8")
    assert '"ticket": "PER-379"' in reproduction_text
    assert f'"commit_sha": "{COMMIT_SHA}"' in reproduction_text
    assert '"deployment_id": "deploy-web-1"' in reproduction_text
    assert SECRET_LI_AT not in reproduction_text

    monkeypatch.setattr(web_harness.database, "ready", lambda: False)
    not_ready = client.get("/readyz")
    assert not_ready.status_code == 503
    assert not_ready.json() == {"status": "not-ready"}


def test_static_assets_use_origin_relative_urls(web_harness: WebHarness) -> None:
    client = web_harness.client
    login_page = client.get("/login")

    assert 'href="/static/app.css"' in login_page.text
    assert client.get("/static/app.css").headers["content-type"].startswith("text/css")

    _login(client)
    dashboard = client.get("/")

    assert 'src="/static/app.js"' in dashboard.text
    assert client.get("/static/app.js").headers["content-type"].startswith("text/javascript")


def test_disconnect_removes_linkedin_session_but_keeps_app_login(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    csrf_token = _login(client)
    pairing = _create_pairing(client, csrf_token)
    assert _complete_pairing(client, pairing).status_code == 200
    assert (
        client.post("/api/linkedin/probe", headers={"X-CSRF-Token": csrf_token}).status_code == 200
    )

    disconnected = client.post(
        "/api/linkedin/disconnect",
        headers={"X-CSRF-Token": csrf_token},
    )

    assert disconnected.status_code == 200
    assert disconnected.json() == {"disconnected": True}
    assert client.get("/api/linkedin/status").json()["connected"] is False
    assert client.get("/").status_code == 200
    second = client.post(
        "/api/linkedin/disconnect",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert second.json() == {"disconnected": False}


def test_delete_data_cascades_records_and_clears_app_cookies(web_harness: WebHarness) -> None:
    client = web_harness.client
    csrf_token = _login(client)
    pairing = _create_pairing(client, csrf_token)
    assert _complete_pairing(client, pairing).status_code == 200
    assert (
        client.post("/api/linkedin/probe", headers={"X-CSRF-Token": csrf_token}).status_code == 200
    )

    response = client.delete("/api/data", headers={"X-CSRF-Token": csrf_token})

    assert response.status_code == 200
    assert response.json() == {"deleted": True}
    assert SESSION_COOKIE not in client.cookies
    assert CSRF_COOKIE not in client.cookies
    assert web_harness.database.get_active_linkedin_session("friend") is None
    assert web_harness.database.list_auth_probes("friend") == []
    assert web_harness.database.delete_user_data("friend") is False
    assert client.get("/api/linkedin/status").status_code == 401


def test_logout_and_data_deletion_revoke_replayed_app_sessions(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    csrf_token = _login(client)
    token_before_logout = client.cookies.get(SESSION_COOKIE)
    assert token_before_logout

    logged_out = client.post(
        "/logout",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert logged_out.status_code == 303
    assert (
        client.get(
            "/api/linkedin/status",
            headers={"Cookie": f"{SESSION_COOKIE}={token_before_logout}"},
        ).status_code
        == 401
    )

    delete_csrf = _login(client)
    token_before_delete = client.cookies.get(SESSION_COOKIE)
    assert token_before_delete
    deleted = client.delete("/api/data", headers={"X-CSRF-Token": delete_csrf})
    assert deleted.status_code == 200
    assert (
        client.get(
            "/api/linkedin/status",
            headers={"Cookie": f"{SESSION_COOKIE}={token_before_delete}"},
        ).status_code
        == 401
    )
    _login(client)
    assert (
        client.get(
            "/api/linkedin/status",
            headers={"Cookie": f"{SESSION_COOKIE}={token_before_delete}"},
        ).status_code
        == 401
    )


def test_login_throttles_guesses_without_echoing_passcodes(web_harness: WebHarness) -> None:
    client = web_harness.client
    for attempt in range(5):
        csrf_token = client.get("/login").cookies.get(CSRF_COOKIE)
        secret_attempt = f"WRONG-SECRET-{attempt}"
        response = client.post(
            "/login",
            data={"passcode": secret_attempt, "csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert response.status_code == 401
        assert secret_attempt not in response.text

    csrf_token = client.get("/login").cookies.get(CSRF_COOKIE)
    blocked_secret = "SIXTH-WRONG-SECRET"
    blocked = client.post(
        "/login",
        data={"passcode": blocked_secret, "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked_secret not in blocked.text


def test_sensitive_request_bodies_are_bounded_before_parsing(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    oversized_login = b"passcode=" + b"S" * 4_096
    login_response = client.post(
        "/login",
        content=oversized_login,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "1",
        },
    )
    assert login_response.status_code == 413
    assert "SSSSSS" not in login_response.text

    logout_response = client.post(
        "/logout",
        content=b"csrf_token=" + b"L" * 4_096,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "1",
        },
    )
    assert logout_response.status_code == 413
    assert "LLLLLL" not in logout_response.text

    oversized_cookie_body = b"C" * (MAX_COOKIE_PAYLOAD_BYTES + 8_193)
    pairing_response = client.post(
        "/api/pairings/synthetic/complete",
        content=oversized_cookie_body,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(oversized_cookie_body)),
        },
    )
    assert pairing_response.status_code == 413
    assert "CCCCCC" not in pairing_response.text


def test_terminal_gate_disables_page_and_rejects_every_live_action(
    web_harness: WebHarness,
) -> None:
    client = web_harness.client
    csrf_token = _login(client)
    pairing = _create_pairing(client, csrf_token)
    web_harness.database.stop_gate("checkpoint")

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Gate stopped" in dashboard.text
    assert "Sanitized reason: checkpoint" in dashboard.text
    assert "Railway deployments" in dashboard.text
    assert (
        client.post(
            "/api/connectors/macos",
            headers={"X-CSRF-Token": csrf_token},
        ).status_code
        == 409
    )
    assert (
        client.post("/api/linkedin/probe", headers={"X-CSRF-Token": csrf_token}).status_code == 409
    )
    assert _complete_pairing(client, pairing).status_code == 409
