from __future__ import annotations

import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from linkedin_cli.mac_connector import CONNECTOR_FILENAME
from linkedin_cli.mac_connector import build_connector_zip
from linkedin_cli.mac_connector_runtime import ConnectorError
from linkedin_cli.mac_connector_runtime import DevToolsWebSocket
from linkedin_cli.mac_connector_runtime import build_chrome_arguments
from linkedin_cli.mac_connector_runtime import normalize_cookie_records
from linkedin_cli.mac_connector_runtime import read_linkedin_cookies
from linkedin_cli.mac_connector_runtime import run_connector
from linkedin_cli.mac_connector_runtime import send_pairing
import linkedin_cli.mac_connector_runtime as runtime


SECRET_LI_AT = "AQED-MAC-CONNECTOR-SECRET"
SECRET_JSESSION = '"ajax:MAC-CONNECTOR-SECRET"'


def _cdp_cookies() -> list[dict[str, object]]:
    return [
        {
            "name": "li_at",
            "value": SECRET_LI_AT,
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": True,
            "expires": 2_000_000_000,
        },
        {
            "name": "JSESSIONID",
            "value": SECRET_JSESSION,
            "domain": "www.linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "expires": -1,
        },
        {
            "name": "lang",
            "value": "v=2&lang=en-us",
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "expires": 2_000_000_000,
        },
        {
            "name": "unrelated",
            "value": "must-not-transfer",
            "domain": ".example.com",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        },
    ]


def test_connector_zip_contains_one_executable_self_deleting_command() -> None:
    token = "pairing-token-MUST-NOT-PRINT"
    payload = build_connector_zip(
        api_base="https://finder.example",
        pairing_id="pairing_123456789",
        pairing_token=token,
        connector_commit="c" * 40,
    )

    with ZipFile(BytesIO(payload)) as archive:
        assert archive.namelist() == [CONNECTOR_FILENAME]
        info = archive.getinfo(CONNECTOR_FILENAME)
        assert (info.external_attr >> 16) & 0o777 == 0o755
        command = archive.read(CONNECTOR_FILENAME).decode("utf-8")

    assert command.startswith("#!/bin/zsh\n")
    assert token in command
    assert "https://finder.example" in command
    assert 'trap cleanup EXIT' in command
    assert 'rm -f -- "$0"' in command
    assert "pbcopy" not in command
    assert "clipboard" not in command.lower()
    assert "LINKEDIN_COOKIE_HEADER" not in command


def test_connector_uses_an_isolated_profile_without_evasion_or_proxying(tmp_path: Path) -> None:
    profile = tmp_path / "temporary-profile"

    arguments = build_chrome_arguments(profile)

    assert f"--user-data-dir={profile}" in arguments
    assert "--remote-debugging-port=0" in arguments
    assert "https://www.linkedin.com/login" in arguments
    rendered = " ".join(arguments).lower()
    assert "proxy" not in rendered
    assert "disable-blink-features" not in rendered
    assert "user-agent" not in rendered


def test_chrome_websocket_accepts_the_chromium_101_reason_phrase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce_bytes = b"n" * 16
    nonce = base64.b64encode(nonce_bytes).decode("ascii")
    accepted = base64.b64encode(
        hashlib.sha1(
            (nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()
    ).decode("ascii")
    response = (
        "HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
        "Upgrade: WebSocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accepted}\r\n\r\n"
    ).encode("ascii")

    class Connection:
        def __init__(self) -> None:
            self.response = response
            self.sent: list[bytes] = []
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            pass

        def sendall(self, payload: bytes) -> None:
            self.sent.append(payload)

        def recv(self, _length: int) -> bytes:
            payload, self.response = self.response, b""
            return payload

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(runtime.secrets, "token_bytes", lambda _length: nonce_bytes)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *_args, **_kwargs: connection)

    client = DevToolsWebSocket.connect("ws://127.0.0.1:9222/devtools/browser/fixture")

    assert isinstance(client, DevToolsWebSocket)
    assert connection.sent[0].startswith(b"GET /devtools/browser/fixture HTTP/1.1\r\n")
    client.close()
    assert connection.closed is True


def test_cdp_cookie_normalization_keeps_only_linkedin_and_required_metadata() -> None:
    records = normalize_cookie_records(_cdp_cookies())

    assert [record["name"] for record in records] == ["JSESSIONID", "lang", "li_at"]
    assert all(str(record["domain"]).lstrip(".").endswith("linkedin.com") for record in records)
    assert next(record for record in records if record["name"] == "li_at")[
        "expirationDate"
    ] == 2_000_000_000.0
    assert "expirationDate" not in next(
        record for record in records if record["name"] == "JSESSIONID"
    )

    with pytest.raises(ConnectorError, match="Sign-in did not produce"):
        normalize_cookie_records(_cdp_cookies()[1:])


def test_pairing_sender_posts_once_without_printing_or_returning_cookies(
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, object] = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int = -1) -> bytes:
            return b'{"connected":true,"probe_pending":true}'

    def opener(request, *, timeout: float):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["connector_commit"] = request.get_header("X-connector-commit")
        captured["content_type"] = request.get_header("Content-type")
        captured["data"] = request.data
        captured["timeout"] = timeout
        return Response()

    result = send_pairing(
        api_base="https://finder.example",
        pairing_id="pairing_123456789",
        pairing_token="single-use-token-1234567890-abcdef",
        connector_commit="c" * 40,
        cookies=normalize_cookie_records(_cdp_cookies()),
        opener=opener,
    )

    assert result == {"connected": True, "probe_pending": True}
    assert captured["url"] == (
        "https://finder.example/api/pairings/pairing_123456789/complete"
    )
    assert captured["authorization"] == "Bearer single-use-token-1234567890-abcdef"
    assert captured["connector_commit"] == "c" * 40
    assert captured["content_type"] == "application/json"
    posted = json.loads(captured["data"])
    assert posted["cookies"][0]["name"] == "JSESSIONID"
    output = capsys.readouterr()
    assert SECRET_LI_AT not in output.out + output.err
    assert SECRET_JSESSION not in output.out + output.err


def test_cookie_read_is_scoped_to_the_linkedin_page_and_exact_urls() -> None:
    calls: list[tuple[str, dict[str, object] | None, str | None]] = []

    class Client:
        def command(self, method, params=None, *, session_id=None):
            calls.append((method, params, session_id))
            if method == "Target.getTargets":
                return {
                    "targetInfos": [
                        {
                            "type": "page",
                            "targetId": "unrelated",
                            "url": "https://example.com/",
                        },
                        {
                            "type": "page",
                            "targetId": "linkedin-page",
                            "url": "https://www.linkedin.com/feed/",
                        },
                    ]
                }
            if method == "Target.attachToTarget":
                return {"sessionId": "linkedin-session"}
            if method == "Network.getCookies":
                return {"cookies": _cdp_cookies()}
            raise AssertionError(f"Unexpected CDP command: {method}")

    cookies = read_linkedin_cookies(Client())  # type: ignore[arg-type]

    assert [cookie["name"] for cookie in cookies] == ["JSESSIONID", "lang", "li_at"]
    assert calls == [
        ("Target.getTargets", None, None),
        (
            "Target.attachToTarget",
            {"targetId": "linkedin-page", "flatten": True},
            None,
        ),
        (
            "Network.getCookies",
            {
                "urls": [
                    "https://www.linkedin.com/",
                    "https://www.linkedin.com/voyager/api/",
                ]
            },
            "linkedin-session",
        ),
    ]


@pytest.mark.parametrize(
    "api_base",
    [
        "http://finder.example",
        "https://finder.example/path",
        "https://user:pass@finder.example",
        "https://finder.example?token=secret",
        "file:///tmp/connector",
    ],
)
def test_pairing_sender_rejects_non_origin_endpoints_before_network(
    api_base: str,
) -> None:
    def opener(*_args, **_kwargs):
        raise AssertionError("Invalid connector configuration must not reach the network.")

    with pytest.raises(ConnectorError, match="invalid Railway origin"):
        send_pairing(
            api_base=api_base,
            pairing_id="pairing_123456789",
            pairing_token="single-use-token-1234567890-abcdef",
            connector_commit="c" * 40,
            cookies=normalize_cookie_records(_cdp_cookies()),
            opener=opener,
        )


def test_connector_cleans_owned_chrome_and_profile_without_printing_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = tmp_path / "ephemeral-profile"
    profile.mkdir()
    secret_token = "single-use-token-MUST-NOT-PRINT-123456"
    captured: dict[str, object] = {}

    class Process:
        def __init__(self) -> None:
            self.running = True
            self.terminated = False

        def poll(self):
            return None if self.running else 0

        def terminate(self) -> None:
            self.terminated = True
            self.running = False

        def wait(self, *, timeout: float):
            captured["wait_timeout"] = timeout
            return 0

    class WebSocket:
        closed = False

        def close(self) -> None:
            self.closed = True

    process = Process()
    websocket = WebSocket()
    monkeypatch.setattr(runtime.tempfile, "mkdtemp", lambda **_kwargs: str(profile))
    monkeypatch.setattr(runtime, "find_chrome_binary", lambda: Path("/Applications/Chrome"))
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(runtime, "_wait_for_devtools_endpoint", lambda *_args: "ws://local")
    monkeypatch.setattr(runtime.DevToolsWebSocket, "connect", lambda _url: websocket)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    monkeypatch.setattr(runtime, "read_linkedin_cookies", lambda _client: _cdp_cookies()[:2])

    def upload(**kwargs):
        captured.update(kwargs)
        return {"connected": True, "probe_pending": True}

    monkeypatch.setattr(runtime, "send_pairing", upload)

    result = run_connector(
        {
            "api_base": "https://finder.example",
            "pairing_id": "pairing_123456789",
            "pairing_token": secret_token,
            "connector_commit": "c" * 40,
        }
    )

    assert result == 0
    assert websocket.closed is True
    assert process.terminated is True
    assert not profile.exists()
    assert captured["pairing_token"] == secret_token
    output = capsys.readouterr().out
    assert secret_token not in output
    assert SECRET_LI_AT not in output
    assert SECRET_JSESSION not in output


def test_connector_sanitizes_unexpected_local_failures_and_cleans_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = tmp_path / "failed-profile"
    profile.mkdir()
    secret_error = "UNEXPECTED-ERROR-MUST-NOT-PRINT"
    monkeypatch.setattr(runtime.tempfile, "mkdtemp", lambda **_kwargs: str(profile))
    monkeypatch.setattr(
        runtime,
        "find_chrome_binary",
        lambda: (_ for _ in ()).throw(RuntimeError(secret_error)),
    )

    result = run_connector(
        {
            "api_base": "https://finder.example",
            "pairing_id": "pairing_123456789",
            "pairing_token": "single-use-token-MUST-NOT-PRINT-123456",
            "connector_commit": "c" * 40,
        }
    )

    assert result == 1
    assert not profile.exists()
    output = capsys.readouterr().out
    assert "unexpected local error" in output
    assert secret_error not in output
