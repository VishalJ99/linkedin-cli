"""Dependency-free runtime embedded in the downloadable macOS connector."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from typing import Any
from typing import Callable
from typing import Iterable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler
from urllib.request import HTTPSHandler
from urllib.request import ProxyHandler
from urllib.request import Request
from urllib.request import build_opener


LINKEDIN_LOGIN_URL = "https://www.linkedin.com/login"
LINKEDIN_COOKIE_URLS = (
    "https://www.linkedin.com/",
    "https://www.linkedin.com/voyager/api/",
)
REQUIRED_COOKIE_NAMES = {"li_at", "JSESSIONID"}
MAX_CDP_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_HTTP_RESPONSE_BYTES = 8_192


class ConnectorError(RuntimeError):
    """A sanitized connector failure safe to display in Terminal."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def build_chrome_arguments(profile_dir: Path) -> list[str]:
    """Return the narrow Chrome launch arguments for one isolated login."""
    return [
        f"--user-data-dir={profile_dir}",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
        "--no-first-run",
        "--no-default-browser-check",
        LINKEDIN_LOGIN_URL,
    ]


def find_chrome_binary() -> Path:
    candidates = (
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path.home() / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise ConnectorError("Google Chrome is required in the Applications folder.")


def normalize_cookie_records(cookies: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Minimize a CDP cookie result to exact LinkedIn-domain records."""
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    now = time.time()
    for raw in cookies:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        value = raw.get("value")
        domain = str(raw.get("domain") or "").strip().lower()
        path = str(raw.get("path") or "/").strip() or "/"
        if not isinstance(name, str) or not isinstance(value, str) or not value:
            continue
        if not _is_linkedin_domain(domain):
            continue
        expires = raw.get("expires")
        if (
            name in REQUIRED_COOKIE_NAMES
            and isinstance(expires, (int, float))
            and not isinstance(expires, bool)
            and 0 < float(expires) <= now
        ):
            continue
        item: dict[str, Any] = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "secure": bool(raw.get("secure", True)),
            "httpOnly": bool(raw.get("httpOnly", False)),
        }
        if (
            isinstance(expires, (int, float))
            and not isinstance(expires, bool)
            and float(expires) > 0
        ):
            item["expirationDate"] = float(expires)
        records[(name, domain, path)] = item

    normalized = sorted(records.values(), key=lambda item: (item["name"], item["domain"], item["path"]))
    present = {item["name"] for item in normalized}
    if not REQUIRED_COOKIE_NAMES <= present:
        raise ConnectorError(
            "Sign-in did not produce the required LinkedIn session. Return to Chrome, "
            "finish signing in, then download a fresh connector."
        )
    return normalized


def send_pairing(
    *,
    api_base: str,
    pairing_id: str,
    pairing_token: str,
    connector_commit: str,
    cookies: list[dict[str, Any]],
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Upload one cookie jar without redirects, proxies, or secret output."""
    origin = _validated_api_origin(api_base)
    if not pairing_id or "/" in pairing_id or len(pairing_id) > 128:
        raise ConnectorError("The connection package is invalid.")
    if len(pairing_token) < 32 or len(pairing_token) > 256:
        raise ConnectorError("The connection package is invalid.")
    if len(connector_commit) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in connector_commit
    ):
        raise ConnectorError("The connection package is invalid.")

    payload = json.dumps({"cookies": cookies}, separators=(",", ":")).encode("utf-8")
    endpoint = f"{origin}/api/pairings/{pairing_id}/complete"
    request = Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {pairing_token}",
            "Content-Type": "application/json",
            "X-Connector-Commit": connector_commit,
        },
    )
    if opener is None:
        client = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirectHandler(),
        )
        opener = client.open
    try:
        with opener(request, timeout=20.0) as response:
            if getattr(response, "status", 0) != 200:
                raise ConnectorError("Railway did not accept the connection.")
            raw_response = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if exc.code in {401, 409}:
            raise ConnectorError(
                "This connector expired or was already used. Download a fresh connector."
            ) from None
        raise ConnectorError("Railway did not accept the connection.") from None
    except (OSError, TimeoutError):
        raise ConnectorError("Could not reach the encrypted Railway connection endpoint.") from None
    if len(raw_response) > MAX_HTTP_RESPONSE_BYTES:
        raise ConnectorError("Railway returned an invalid connection response.")
    try:
        result = json.loads(raw_response)
    except (TypeError, ValueError):
        raise ConnectorError("Railway returned an invalid connection response.") from None
    if result != {"connected": True, "probe_pending": True}:
        raise ConnectorError("Railway returned an invalid connection response.")
    return result


class DevToolsWebSocket:
    """Small bounded WebSocket client sufficient for local Chrome CDP."""

    def __init__(self, connection: socket.socket, buffered: bytes = b"") -> None:
        self._connection = connection
        self._buffer = bytearray(buffered)
        self._next_id = 1

    @classmethod
    def connect(cls, websocket_url: str) -> "DevToolsWebSocket":
        parsed = urlsplit(websocket_url)
        if (
            parsed.scheme != "ws"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.port is None
            or not parsed.path.startswith("/devtools/browser/")
        ):
            raise ConnectorError("Chrome exposed an invalid local debugging endpoint.")
        connection = socket.create_connection((parsed.hostname, parsed.port), timeout=5.0)
        connection.settimeout(10.0)
        nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        connection.sendall(request)
        header, buffered = _receive_http_header(connection)
        status_line, *header_lines = header.decode("iso-8859-1").split("\r\n")
        headers = {}
        for line in header_lines:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1((nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        connection_tokens = {
            token.strip().lower()
            for token in headers.get("connection", "").split(",")
            if token.strip()
        }
        if (
            status_line != "HTTP/1.1 101 Switching Protocols"
            or headers.get("upgrade", "").lower() != "websocket"
            or "upgrade" not in connection_tokens
            or headers.get("sec-websocket-accept") != expected
        ):
            connection.close()
            raise ConnectorError("Chrome rejected the local debugging connection.")
        return cls(connection, buffered)

    def command(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        command_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"id": command_id, "method": method}
        if params:
            message["params"] = params
        if session_id:
            message["sessionId"] = session_id
        self._send_frame(0x1, json.dumps(message, separators=(",", ":")).encode("utf-8"))
        while True:
            opcode, payload = self._receive_message()
            if opcode == 0x8:
                raise ConnectorError("Chrome closed the local debugging connection.")
            if opcode != 0x1:
                continue
            try:
                response = json.loads(payload)
            except (TypeError, ValueError):
                raise ConnectorError("Chrome returned an invalid local debugging response.") from None
            if response.get("id") != command_id:
                continue
            if "error" in response or not isinstance(response.get("result"), dict):
                raise ConnectorError("Chrome could not read the LinkedIn session.")
            return response["result"]

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except (ConnectorError, OSError):
            pass
        try:
            self._connection.close()
        except OSError:
            pass

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if len(payload) > MAX_CDP_MESSAGE_BYTES:
            raise ConnectorError("Chrome debugging message exceeded the safety limit.")
        first = 0x80 | opcode
        mask = secrets.token_bytes(4)
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", first, 0x80 | length)
        elif length <= 0xFFFF:
            header = struct.pack("!BBH", first, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", first, 0x80 | 127, length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self._connection.sendall(header + mask + masked)

    def _receive_message(self) -> tuple[int, bytes]:
        fragments: list[bytes] = []
        message_opcode: int | None = None
        total = 0
        while True:
            first, second = self._read_exact(2)
            if first & 0x70:
                raise ConnectorError("Chrome returned an invalid WebSocket frame.")
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            if masked:
                raise ConnectorError("Chrome returned an invalid WebSocket frame.")
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > MAX_CDP_MESSAGE_BYTES or total + length > MAX_CDP_MESSAGE_BYTES:
                raise ConnectorError("Chrome debugging response exceeded the safety limit.")
            payload = self._read_exact(length)
            if opcode >= 0x8 and (not final or length > 125):
                raise ConnectorError("Chrome returned an invalid WebSocket frame.")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode in {0x8, 0xA}:
                return opcode, payload
            if opcode in {0x1, 0x2}:
                if message_opcode is not None:
                    raise ConnectorError("Chrome returned an invalid WebSocket frame.")
                message_opcode = opcode
                fragments = [payload]
                total = len(payload)
            elif opcode == 0x0 and message_opcode is not None:
                fragments.append(payload)
                total += len(payload)
            else:
                raise ConnectorError("Chrome returned an invalid WebSocket frame.")
            if final and message_opcode is not None:
                return message_opcode, b"".join(fragments)

    def _read_exact(self, length: int) -> bytes:
        while len(self._buffer) < length:
            chunk = self._connection.recv(min(65_536, length - len(self._buffer)))
            if not chunk:
                raise ConnectorError("Chrome closed the local debugging connection.")
            self._buffer.extend(chunk)
        result = bytes(self._buffer[:length])
        del self._buffer[:length]
        return result


def read_linkedin_cookies(client: DevToolsWebSocket) -> list[dict[str, Any]]:
    """Read cookies for explicit LinkedIn URLs from the isolated page target."""
    targets = client.command("Target.getTargets").get("targetInfos")
    if not isinstance(targets, list):
        raise ConnectorError("Chrome did not expose the LinkedIn login page.")
    target_id = None
    for target in targets:
        if not isinstance(target, dict) or target.get("type") != "page":
            continue
        parsed = urlsplit(str(target.get("url") or ""))
        if parsed.scheme == "https" and _is_linkedin_domain(parsed.hostname or ""):
            target_id = target.get("targetId")
            break
    if not isinstance(target_id, str) or not target_id:
        raise ConnectorError("Return to the LinkedIn Chrome window and finish signing in.")
    attached = client.command(
        "Target.attachToTarget",
        {"targetId": target_id, "flatten": True},
    )
    session_id = attached.get("sessionId")
    if not isinstance(session_id, str) or not session_id:
        raise ConnectorError("Chrome could not open the isolated LinkedIn session.")
    result = client.command(
        "Network.getCookies",
        {"urls": list(LINKEDIN_COOKIE_URLS)},
        session_id=session_id,
    )
    cookies = result.get("cookies")
    if not isinstance(cookies, list):
        raise ConnectorError("Chrome could not read the isolated LinkedIn session.")
    return normalize_cookie_records(cookies)


def run_connector(config: dict[str, str]) -> int:
    """Run one explicit login/read/upload operation and clean every local artifact."""
    profile_dir: Path | None = None
    chrome_process: subprocess.Popen[Any] | None = None
    websocket: DevToolsWebSocket | None = None
    try:
        print("LinkedIn Conversation Finder")
        print("Opening a temporary Chrome profile. Sign into LinkedIn there.")
        print("No cookie value will be displayed, copied, or saved on this Mac.")
        profile_dir = Path(tempfile.mkdtemp(prefix="linkedin-connector-"))
        profile_dir.chmod(0o700)
        chrome_binary = find_chrome_binary()
        chrome_process = subprocess.Popen(
            [str(chrome_binary), *build_chrome_arguments(profile_dir)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        websocket_url = _wait_for_devtools_endpoint(profile_dir, chrome_process)
        websocket = DevToolsWebSocket.connect(websocket_url)
        input("After LinkedIn finishes loading, return here and press Return to connect: ")
        cookies = read_linkedin_cookies(websocket)
        send_pairing(
            api_base=config.get("api_base", ""),
            pairing_id=config.get("pairing_id", ""),
            pairing_token=config.get("pairing_token", ""),
            connector_commit=config.get("connector_commit", ""),
            cookies=cookies,
        )
        print("Connected securely. Return to the website; it will run the first read probe once.")
        return 0
    except (ConnectorError, EOFError, KeyboardInterrupt) as exc:
        if isinstance(exc, ConnectorError):
            print(f"Connector stopped: {exc}")
        else:
            print("Connector canceled. No LinkedIn session was transferred.")
        return 1
    except Exception:
        print("Connector stopped because of an unexpected local error. No session was transferred.")
        return 1
    finally:
        if websocket is not None:
            websocket.close()
        if chrome_process is not None and chrome_process.poll() is None:
            chrome_process.terminate()
            try:
                chrome_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome_process.kill()
                chrome_process.wait(timeout=5)
        if profile_dir is not None:
            shutil.rmtree(profile_dir, ignore_errors=True)


def _wait_for_devtools_endpoint(
    profile_dir: Path,
    chrome_process: subprocess.Popen[Any],
    timeout_seconds: float = 30.0,
) -> str:
    endpoint_file = profile_dir / "DevToolsActivePort"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if chrome_process.poll() is not None:
            raise ConnectorError("Chrome closed before LinkedIn sign-in started.")
        try:
            lines = endpoint_file.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, OSError):
            lines = []
        if len(lines) >= 2 and lines[0].isdigit() and lines[1].startswith("/devtools/browser/"):
            return f"ws://127.0.0.1:{int(lines[0])}{lines[1]}"
        time.sleep(0.1)
    raise ConnectorError("Chrome did not open its isolated local connection in time.")


def _receive_http_header(connection: socket.socket) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectorError("Chrome closed the local debugging connection.")
        data.extend(chunk)
        if len(data) > 16_384:
            raise ConnectorError("Chrome returned an invalid debugging handshake.")
    header, buffered = bytes(data).split(b"\r\n\r\n", 1)
    return header, buffered


def _validated_api_origin(value: str) -> str:
    parsed = urlsplit(value)
    is_local = parsed.hostname in {"localhost", "127.0.0.1", "testserver"}
    if (
        parsed.scheme not in ({"http", "https"} if is_local else {"https"})
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ConnectorError("The connection package has an invalid Railway origin.")
    return value.rstrip("/")


def _is_linkedin_domain(domain: str) -> bool:
    normalized = domain.strip().lower().lstrip(".")
    return normalized == "linkedin.com" or normalized.endswith(".linkedin.com")
