"""Authentication helpers for linkedin-cli."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
import re
from typing import Any
from typing import Iterable

from linkedin_api import Linkedin
from requests.cookies import create_cookie
from requests.cookies import RequestsCookieJar

from .config import AppConfig
from .constants import COOKIE_REQUIRED_NAMES
from .constants import ENV_BROWSER
from .constants import ENV_COOKIE_HEADER
from .constants import ENV_JSESSIONID
from .constants import ENV_LI_AT
from .constants import SUPPORTED_BROWSERS

_LINKEDIN_DOMAINS = {
    "linkedin.com",
    ".linkedin.com",
    "www.linkedin.com",
    ".www.linkedin.com",
}

_COOKIE_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_LINKEDIN_HOST_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*linkedin\.com$")
_CHROME_SAME_SITE_VALUES = {
    "no_restriction": "None",
    "lax": "Lax",
    "strict": "Strict",
    "unspecified": "Unspecified",
}
_AUTH_STOP_REASONS = {
    "authwall",
    "challenge",
    "checkpoint",
    "empty-redirect",
    "login",
    "redirect",
    "self-redirect-loop",
    "session-rejected",
}
_AUTH_STOP_STATUS_CODES = {401, 403, 429}


class AuthenticationError(RuntimeError):
    """Raised when a usable LinkedIn session cannot be resolved."""


@dataclass
class AuthSession:
    """Resolved LinkedIn auth cookies and metadata."""

    cookie_jar: RequestsCookieJar
    source: str
    browser: str | None = None
    proxy: str | None = None

    @property
    def li_at(self) -> str:
        return _first_cookie_value(self.cookie_jar, "li_at")

    @property
    def jsessionid(self) -> str:
        return _first_cookie_value(self.cookie_jar, "JSESSIONID").strip('"')

    @property
    def cookie_string(self) -> str:
        pairs = []
        for cookie in self.cookie_jar:
            pairs.append(f"{cookie.name}={cookie.value}")
        return "; ".join(pairs)

    @property
    def cookie_count(self) -> int:
        return sum(1 for _ in self.cookie_jar)

    @property
    def cookie_names(self) -> list[str]:
        return sorted({cookie.name for cookie in self.cookie_jar})

    def has_required_cookies(self) -> bool:
        return _has_required_cookies(self.cookie_jar)

    def as_playwright_cookies(self) -> list[dict[str, object]]:
        cookies = []
        for cookie in self.cookie_jar:
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain or ".linkedin.com",
                    "path": cookie.path or "/",
                    "httpOnly": bool(cookie._rest.get("HttpOnly")),
                    "secure": bool(cookie.secure),
                    "sameSite": "Lax",
                }
            )
        return cookies


def auth_session_from_cookie_records(
    records: Any,
    *,
    source: str = "extension",
    proxy: str | None = None,
) -> AuthSession:
    """Build an auth session from Chrome-style LinkedIn cookie records.

    The function intentionally reports only record positions and field names in
    validation errors. Cookie values remain confined to the returned cookie jar.
    """
    if not isinstance(records, list):
        raise AuthenticationError("Cookie records must be a list.")

    jar = RequestsCookieJar()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise AuthenticationError(f"Cookie record {index} must be an object.")

        name = record.get("name")
        if not isinstance(name, str) or not name or not _COOKIE_NAME_PATTERN.fullmatch(name):
            raise AuthenticationError(f"Cookie record {index} has an invalid name.")

        value = record.get("value")
        if not isinstance(value, str) or any(character in value for character in "\r\n\x00"):
            raise AuthenticationError(f"Cookie record {index} has an invalid value.")

        domain = _normalize_cookie_domain(record.get("domain"), index=index)
        path = _normalize_cookie_path(record.get("path", "/"), index=index)
        secure = _cookie_boolean(record, "secure", index=index, default=False)
        http_only = _cookie_boolean(record, "httpOnly", index=index, default=False)
        _cookie_boolean(record, "hostOnly", index=index, default=not domain.startswith("."))
        expires = _cookie_expiry(record, index=index)
        same_site = _cookie_same_site(record, index=index)

        rest: dict[str, object] = {"SameSite": same_site}
        if http_only:
            rest["HttpOnly"] = True
        jar.set_cookie(
            create_cookie(
                name=name,
                value=value,
                domain=domain,
                path=path,
                secure=secure,
                expires=expires,
                discard=expires is None,
                rest=rest,
            )
        )

    if not _has_required_cookies(jar):
        raise AuthenticationError(
            "Cookie records must include nonempty li_at and JSESSIONID cookies."
        )
    return AuthSession(cookie_jar=jar, source=source, proxy=proxy)


def resolve_auth_session(config: AppConfig) -> AuthSession:
    """Load LinkedIn cookies from env or browser storage."""
    env_header_session = _load_from_cookie_header(config)
    if env_header_session is not None:
        return env_header_session

    env_session = _load_from_env(config)
    if env_session is not None:
        return env_session

    browser_session = _load_from_browser(config)
    if browser_session is not None:
        return browser_session

    raise AuthenticationError(
        "No LinkedIn cookies found. Set LINKEDIN_COOKIE_HEADER or LINKEDIN_LI_AT/LINKEDIN_JSESSIONID, or log into linkedin.com in a supported browser."
    )


def build_api_client(session: AuthSession, config: AppConfig):
    """Create the unofficial LinkedIn Voyager client from resolved cookies."""
    proxies = {}
    if config.runtime.proxy:
        proxies = {
            "http": config.runtime.proxy,
            "https": config.runtime.proxy,
        }
    return Linkedin(
        "",
        "",
        authenticate=True,
        cookies=session.cookie_jar,
        proxies=proxies,
    )


def validate_auth_session(session: AuthSession, config: AppConfig) -> dict[str, Any]:
    """Perform a lightweight profile request using the resolved cookies."""
    from .transport import LinkedInTransport

    try:
        payload = LinkedInTransport(session, config).get_me()
    except Exception as exc:  # pragma: no cover - depends on live cookies/network
        raise AuthenticationError(f"LinkedIn auth validation failed: {exc}") from exc
    if not isinstance(payload, dict) or not payload:
        raise AuthenticationError("LinkedIn auth validation failed: empty profile payload.")
    return payload


def inspect_auth_session(session: AuthSession, config: AppConfig) -> dict[str, Any]:
    """Run the basic auth read without collapsing diagnostics into a generic error."""
    from .transport import LinkedInRedirectError
    from .transport import LinkedInAuthContentError
    from .transport import LinkedInHTTPError
    from .transport import LinkedInSchemaError
    from .transport import LinkedInTransport
    from .transport import LinkedInTransportError

    try:
        payload = LinkedInTransport(session, config).get_me()
    except LinkedInRedirectError as exc:
        return {
            "ok": False,
            "kind": exc.details.reason,
            "error": str(exc),
            "status_code": exc.details.status_code,
            "location": exc.details.location,
            "url": exc.details.url,
        }
    except LinkedInHTTPError as exc:
        return {
            "ok": False,
            "kind": "http-error",
            "error": str(exc),
            "status_code": exc.status_code,
            "url": exc.url,
        }
    except LinkedInAuthContentError as exc:
        return {
            "ok": False,
            "kind": exc.reason,
            "status_code": 200,
            "url": exc.url,
        }
    except LinkedInSchemaError:
        return {
            "ok": False,
            "kind": "schema-drift",
            "status_code": 200,
        }
    except LinkedInTransportError as exc:
        return {
            "ok": False,
            "kind": "transport-error",
            "error": str(exc),
        }
    except Exception as exc:  # pragma: no cover - depends on live cookies/network
        return {
            "ok": False,
            "kind": exc.__class__.__name__.replace("_", "-").lower(),
            "error": str(exc),
        }
    if not isinstance(payload, dict) or not payload:
        return {
            "ok": False,
            "kind": "invalid-payload",
            "error": "LinkedIn returned an empty profile payload.",
        }
    return {
        "ok": True,
        "kind": "profile-read",
        "payload": payload,
    }


def probe_read_access(
    session: AuthSession,
    config: AppConfig,
    *,
    public_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Run non-following probes against Voyager endpoints for diagnostics."""
    from .transport import LinkedInTransport

    transport = LinkedInTransport(session, config)
    checks = {
        "voyager_me": ("/me", {}),
        "voyager_feed": (
            "/feed/updatesV2",
            {
                "params": {"count": "1", "q": "chronFeed"},
                "headers": {"accept": "application/vnd.linkedin.normalized+json+2.1"},
            },
        ),
    }

    results: dict[str, dict[str, Any]] = {}
    for name, (uri, kwargs) in checks.items():
        try:
            results[name] = transport.probe(
                uri,
                params=kwargs.get("params"),
                headers=kwargs.get("headers"),
            )
            if "headers" in kwargs:
                results[name]["headers_used"] = list(kwargs["headers"].keys())
        except Exception as exc:  # pragma: no cover - live network behavior
            results[name] = {
                "ok": False,
                "kind": exc.__class__.__name__.replace("_", "-").lower(),
                "error": str(exc),
            }
        if _is_auth_stop(results[name]):
            break
    if public_id and not any(_is_auth_stop(result) for result in results.values()):
        try:
            results["voyager_profile"] = transport.probe_profile(public_id)
        except Exception as exc:  # pragma: no cover - live network behavior
            results["voyager_profile"] = {
                "ok": False,
                "kind": exc.__class__.__name__.replace("_", "-").lower(),
                "error": str(exc),
            }
    elif not public_id and not any(_is_auth_stop(result) for result in results.values()):
        results["voyager_profile"] = {
            "ok": False,
            "kind": "missing-public-id",
            "error": "Authenticated profile did not include a public identifier.",
        }
    return results


def collect_auth_diagnostics(config: AppConfig) -> dict[str, Any]:
    """Resolve the current auth session and return diagnostic details."""
    session = resolve_auth_session(config)
    return collect_auth_diagnostics_for_session(session, config)


def collect_auth_diagnostics_for_session(
    session: AuthSession,
    config: AppConfig,
) -> dict[str, Any]:
    """Return diagnostic details for an already resolved auth session."""
    if not session.has_required_cookies():
        raise AuthenticationError("LinkedIn session is missing required cookies.")

    validation = inspect_auth_session(session, config)
    payload = validation.get("payload", {}) if validation.get("ok") else {}
    public_id, full_name = _extract_identity(payload)
    probes = (
        probe_read_access(session, config, public_id=public_id or None)
        if validation.get("ok")
        else {}
    )
    required_probes = {"voyager_me", "voyager_feed", "voyager_profile"}
    probes_ok = required_probes <= probes.keys() and all(
        bool(probes[name].get("ok")) for name in required_probes
    )
    return {
        "ok": bool(validation.get("ok")) and probes_ok,
        "source": session.source,
        "browser": session.browser,
        "cookie_count": session.cookie_count,
        "cookie_names": session.cookie_names,
        "public_id": public_id,
        "full_name": full_name,
        "validation": {
            "ok": bool(validation.get("ok")),
            "kind": validation.get("kind", ""),
            "error": validation.get("error", ""),
            "status_code": validation.get("status_code"),
            "location": validation.get("location"),
        },
        "probes": probes,
        "hint": _build_auth_hint(session, validation, probes),
    }


def collect_gate_diagnostics_for_session(
    session: AuthSession,
    config: AppConfig,
) -> dict[str, Any]:
    """Run only the two reads required by the Railway feasibility gate.

    The inherited CLI diagnostics also probe feed access and repeat ``/me``.
    Those reads are useful interactively but are outside the gate acceptance
    contract and would unnecessarily expand its account-risk surface.
    """
    if not session.has_required_cookies():
        raise AuthenticationError("LinkedIn session is missing required cookies.")

    validation = inspect_auth_session(session, config)
    payload = validation.get("payload", {}) if validation.get("ok") else {}
    public_id, full_name = _extract_identity(payload)
    probes: dict[str, dict[str, Any]] = {}
    if validation.get("ok"):
        if public_id:
            from .transport import LinkedInTransport

            try:
                probes["voyager_profile"] = LinkedInTransport(
                    session, config
                ).probe_profile(public_id)
            except Exception as exc:  # pragma: no cover - live network behavior
                probes["voyager_profile"] = {
                    "ok": False,
                    "kind": exc.__class__.__name__.replace("_", "-").lower(),
                    "error": str(exc),
                }
        else:
            probes["voyager_profile"] = {
                "ok": False,
                "kind": "missing-public-id",
                "error": "Authenticated profile did not include a public identifier.",
            }
    profile_probe = probes.get("voyager_profile", {})
    return {
        "ok": bool(validation.get("ok")) and bool(profile_probe.get("ok")),
        "source": session.source,
        "browser": session.browser,
        "cookie_count": session.cookie_count,
        "cookie_names": session.cookie_names,
        "public_id": public_id,
        "full_name": full_name,
        "validation": {
            "ok": bool(validation.get("ok")),
            "kind": validation.get("kind", ""),
            "error": validation.get("error", ""),
            "status_code": validation.get("status_code"),
            "location": validation.get("location"),
        },
        "probes": probes,
        "hint": _build_auth_hint(session, validation, probes),
    }


def _extract_identity(payload: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "", ""
    mini_profile = payload.get("miniProfile")
    if not isinstance(mini_profile, dict):
        mini_profile = {}
    public_id = next(
        (
            candidate.strip()
            for candidate in (
                mini_profile.get("publicIdentifier"),
                payload.get("plainId"),
                payload.get("publicIdentifier"),
            )
            if isinstance(candidate, str) and candidate.strip()
        ),
        "",
    )
    full_name = " ".join(
        part.strip()
        for part in (payload.get("firstName"), payload.get("lastName"))
        if isinstance(part, str) and part.strip()
    )
    return public_id, full_name


def _is_auth_stop(result: dict[str, Any]) -> bool:
    reason = str(result.get("reason") or result.get("kind") or "").lower()
    return reason in _AUTH_STOP_REASONS or result.get("status_code") in _AUTH_STOP_STATUS_CODES


def _build_auth_hint(
    session: AuthSession,
    validation: dict[str, Any],
    probes: dict[str, dict[str, Any]],
) -> str:
    redirect_reasons = {
        "redirect",
        "self-redirect-loop",
        "login",
        "checkpoint",
        "authwall",
        "challenge",
    }
    saw_redirects = validation.get("kind") in redirect_reasons or any(
        result.get("reason") in redirect_reasons for result in probes.values()
    )
    if not saw_redirects:
        if validation.get("ok") and all(result.get("ok") for result in probes.values()):
            return ""
        return "Basic auth did not complete cleanly. Review the probe details above."
    if session.cookie_count <= len(COOKIE_REQUIRED_NAMES):
        return (
            "Only the minimum cookies are loaded. LinkedIn often requires a fuller linkedin.com "
            "cookie jar. Try LINKEDIN_COOKIE_HEADER with the full Cookie header or browser extraction."
        )
    return (
        "LinkedIn is redirecting authenticated reads even with the current cookie jar. "
        "This usually means authwall/checkpoint behavior or missing browser-like request context."
    )


def _load_from_cookie_header(config: AppConfig) -> AuthSession | None:
    raw_header = os.getenv(ENV_COOKIE_HEADER, "").strip()
    if not raw_header:
        return None

    jar = RequestsCookieJar()
    for name, value in _parse_cookie_header(raw_header).items():
        jar.set(
            name,
            value,
            domain=".linkedin.com",
            path="/",
        )
    if not _has_required_cookies(jar):
        raise AuthenticationError(
            "LINKEDIN_COOKIE_HEADER was provided but does not include li_at and JSESSIONID."
        )
    return AuthSession(cookie_jar=jar, source="env-cookie-header", proxy=config.runtime.proxy)


def _load_from_env(config: AppConfig) -> AuthSession | None:
    li_at = os.getenv(ENV_LI_AT, "").strip()
    jsessionid = os.getenv(ENV_JSESSIONID, "").strip()
    if not li_at or not jsessionid:
        return None

    jar = RequestsCookieJar()
    jar.set("li_at", li_at, domain=".linkedin.com", path="/")
    jar.set("JSESSIONID", jsessionid, domain=".linkedin.com", path="/")
    return AuthSession(cookie_jar=jar, source="env", proxy=config.runtime.proxy)


def _load_from_browser(config: AppConfig) -> AuthSession | None:
    try:
        import browser_cookie3
    except ImportError as exc:  # pragma: no cover - dependency guarded by packaging
        raise AuthenticationError(
            "browser-cookie3 is required for browser cookie extraction."
        ) from exc

    browser_preference = os.getenv(ENV_BROWSER, "").strip().lower() or config.browser.preferred
    loaders = {
        "chrome": browser_cookie3.chrome,
        "chromium": browser_cookie3.chromium,
        "brave": browser_cookie3.brave,
        "edge": browser_cookie3.edge,
        "firefox": browser_cookie3.firefox,
    }

    for browser in _ordered_browser_names(browser_preference):
        loader = loaders.get(browser)
        if loader is None:
            continue
        try:
            jar = loader()
        except Exception:
            continue
        session = _session_from_cookie_jar(
            jar,
            source="browser",
            browser=browser,
            proxy=config.runtime.proxy,
        )
        if session is not None:
            return session
    return None


def _ordered_browser_names(preferred: str) -> Iterable[str]:
    if preferred and preferred in SUPPORTED_BROWSERS:
        yield preferred
    for browser in SUPPORTED_BROWSERS:
        if browser != preferred:
            yield browser


def _session_from_cookie_jar(
    jar: RequestsCookieJar,
    *,
    source: str,
    browser: str | None,
    proxy: str | None,
) -> AuthSession | None:
    linkedin_jar = RequestsCookieJar()
    for cookie in jar:
        if not _is_linkedin_domain(cookie.domain or ""):
            continue
        _copy_cookie(linkedin_jar, cookie)
    if _has_required_cookies(linkedin_jar):
        return AuthSession(
            cookie_jar=linkedin_jar,
            source=source,
            browser=browser,
            proxy=proxy,
        )
    return None


def _copy_cookie(target: RequestsCookieJar, cookie) -> None:
    target.set_cookie(
        create_cookie(
            name=cookie.name,
            value=cookie.value,
            domain=cookie.domain or ".linkedin.com",
            path=cookie.path or "/",
            secure=bool(cookie.secure),
            expires=getattr(cookie, "expires", None),
            rest=dict(getattr(cookie, "_rest", {})),
        )
    )


def _has_required_cookies(jar: RequestsCookieJar) -> bool:
    return all(
        any(
            cookie.name == name
            and isinstance(cookie.value, str)
            and _required_cookie_is_nonempty(name, cookie.value)
            for cookie in jar
        )
        for name in COOKIE_REQUIRED_NAMES
    )


def _first_cookie_value(jar: RequestsCookieJar, name: str) -> str:
    fallback = ""
    for cookie in jar:
        if cookie.name == name and isinstance(cookie.value, str):
            fallback = fallback or cookie.value
            if _required_cookie_is_nonempty(name, cookie.value):
                return cookie.value
    return fallback


def _required_cookie_is_nonempty(name: str, value: str) -> bool:
    normalized = value.strip()
    if name == "JSESSIONID":
        normalized = normalized.strip('"').strip()
    return bool(normalized)


def _normalize_cookie_domain(value: Any, *, index: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuthenticationError(f"Cookie record {index} has an invalid domain.")
    normalized = value.lower()
    host = normalized[1:] if normalized.startswith(".") else normalized
    if not _LINKEDIN_HOST_PATTERN.fullmatch(host):
        raise AuthenticationError(f"Cookie record {index} has a non-LinkedIn domain.")
    return normalized


def _normalize_cookie_path(value: Any, *, index: int) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or any(character in value for character in "\r\n\x00")
    ):
        raise AuthenticationError(f"Cookie record {index} has an invalid path.")
    return value


def _cookie_boolean(
    record: dict[str, Any],
    field: str,
    *,
    index: int,
    default: bool,
) -> bool:
    value = record.get(field, default)
    if not isinstance(value, bool):
        raise AuthenticationError(f"Cookie record {index} has an invalid {field} field.")
    return value


def _cookie_expiry(record: dict[str, Any], *, index: int) -> int | None:
    is_session = _cookie_boolean(record, "session", index=index, default=False)
    value = record.get("expirationDate")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuthenticationError(f"Cookie record {index} has an invalid expirationDate field.")
    if not math.isfinite(value) or value < 0:
        raise AuthenticationError(f"Cookie record {index} has an invalid expirationDate field.")
    if is_session:
        return None
    return int(value)


def _cookie_same_site(record: dict[str, Any], *, index: int) -> str:
    value = record.get("sameSite", "unspecified")
    if not isinstance(value, str) or value not in _CHROME_SAME_SITE_VALUES:
        raise AuthenticationError(f"Cookie record {index} has an invalid sameSite field.")
    return _CHROME_SAME_SITE_VALUES[value]


def _is_linkedin_domain(domain: str) -> bool:
    if not isinstance(domain, str) or not domain:
        return False
    normalized = domain.lower()
    if normalized in _LINKEDIN_DOMAINS:
        return True
    host = normalized[1:] if normalized.startswith(".") else normalized
    return bool(_LINKEDIN_HOST_PATTERN.fullmatch(host))


def _parse_cookie_header(raw_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for segment in raw_header.split(";"):
        item = segment.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        cookies[name] = value
    return cookies
