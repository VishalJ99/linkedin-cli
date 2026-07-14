from __future__ import annotations

import json

import pytest
from requests import Response
from requests.cookies import RequestsCookieJar

from linkedin_cli.auth import AuthSession
from linkedin_cli.config import load_config
from linkedin_cli.transport import LinkedInAuthContentError
from linkedin_cli.transport import LinkedInSchemaError
from linkedin_cli.transport import LinkedInVoyagerTransport
from linkedin_cli.transport import _classify_redirect


def _response(
    status_code: int, *, url: str, location: str | None = None, set_cookie: str = ""
) -> Response:
    response = Response()
    response.status_code = status_code
    response.url = url
    if location is not None:
        response.headers["location"] = location
    if set_cookie:
        response.headers["set-cookie"] = set_cookie
    return response


def _html_response(url: str, html: str) -> Response:
    response = Response()
    response.status_code = 200
    response.url = url
    response.encoding = "utf-8"
    response._content = html.encode("utf-8")
    return response


def test_classify_redirect_marks_session_rejected() -> None:
    response = _response(
        302,
        url="https://www.linkedin.com/voyager/api/feed/updatesV2",
        location="https://www.linkedin.com/voyager/api/feed/updatesV2",
        set_cookie="li_at=delete me; Domain=.linkedin.com; Path=/",
    )

    assert _classify_redirect(response) == "self-redirect-loop"


def test_build_headers_includes_csrf_token() -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    session = AuthSession(cookie_jar=jar, source="env")
    transport = LinkedInVoyagerTransport(session, config)

    headers = transport._build_headers()

    assert headers["csrf-token"] == "ajax:123"
    assert headers["x-restli-protocol-version"] == "2.0.0"
    assert "cookie" not in headers


def test_transport_disables_requests_environment_proxies() -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    session = AuthSession(cookie_jar=jar, source="extension")

    transport = LinkedInVoyagerTransport(session, config)

    assert transport._session.trust_env is False


def test_probe_marks_http_errors_unhealthy(monkeypatch) -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    session = AuthSession(cookie_jar=jar, source="env")
    transport = LinkedInVoyagerTransport(session, config)
    calls = {}

    def fake_request(resource, *, params=None, headers=None, allow_redirects=False):
        calls["resource"] = resource
        calls["params"] = params
        calls["headers"] = headers
        calls["allow_redirects"] = allow_redirects
        return _response(
            410, url="https://www.linkedin.com/voyager/api/identity/profiles/jane-doe/profileView"
        )

    monkeypatch.setattr(transport, "_request", fake_request)

    result = transport.probe(
        "/identity/profiles/jane-doe/profileView",
        headers={"accept": "application/vnd.linkedin.normalized+json+2.1"},
    )

    assert result["ok"] is False
    assert result["status_code"] == 410
    assert result["reason"] == "http-error"
    assert calls["headers"] == {"accept": "application/vnd.linkedin.normalized+json+2.1"}


@pytest.mark.parametrize("status_code", [401, 403, 429, 503])
def test_profile_probe_preserves_http_error_status(monkeypatch, status_code) -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    session = AuthSession(cookie_jar=jar, source="extension")
    transport = LinkedInVoyagerTransport(session, config)
    profile_url = "https://www.linkedin.com/in/jane-doe/"

    def return_http_error(resource, **_kwargs):
        assert resource == profile_url
        return _response(status_code, url=profile_url)

    monkeypatch.setattr(transport, "_request", return_http_error)

    result = transport.probe_profile("jane-doe")

    assert result == {
        "ok": False,
        "status_code": status_code,
        "url": profile_url,
        "reason": "http-error",
    }


def test_profile_probe_classifies_success_code_login_content_as_terminal(monkeypatch) -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    transport = LinkedInVoyagerTransport(AuthSession(jar, source="extension"), config)
    html = (
        "<html><head><title>LinkedIn Login, Sign in | LinkedIn</title></head>"
        '<body><form action="/uas/login-submit"></form></body></html>'
    )
    monkeypatch.setattr(
        transport,
        "_request_profile_page",
        lambda _public_id: _html_response("https://www.linkedin.com/in/jane-doe/", html),
    )

    assert transport.probe_profile("jane-doe") == {
        "ok": False,
        "status_code": 200,
        "url": "https://www.linkedin.com/in/jane-doe/",
        "reason": "login",
    }


def test_profile_probe_classifies_success_code_schema_drift_as_terminal(monkeypatch) -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    transport = LinkedInVoyagerTransport(AuthSession(jar, source="extension"), config)
    monkeypatch.setattr(
        transport,
        "_request_profile_page",
        lambda _public_id: _html_response(
            "https://www.linkedin.com/in/jane-doe/",
            "<html><head><title>Jane Doe | LinkedIn</title></head><body></body></html>",
        ),
    )

    assert transport.probe_profile("jane-doe") == {
        "ok": False,
        "status_code": 200,
        "reason": "profile-schema-drift",
    }


@pytest.mark.parametrize(
    ("html", "exception_type", "reason"),
    [
        (
            "<html><head><title>LinkedIn Login, Sign in | LinkedIn</title></head>"
            '<body><form action="/uas/login-submit"></form></body></html>',
            LinkedInAuthContentError,
            "login",
        ),
        (
            "<html><head><title>Unexpected response</title></head><body></body></html>",
            LinkedInSchemaError,
            None,
        ),
    ],
)
def test_me_read_distinguishes_terminal_auth_content_and_schema_drift(
    monkeypatch,
    html,
    exception_type,
    reason,
) -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    transport = LinkedInVoyagerTransport(AuthSession(jar, source="extension"), config)
    monkeypatch.setattr(
        transport,
        "_request",
        lambda *_args, **_kwargs: _html_response(
            "https://www.linkedin.com/voyager/api/me",
            html,
        ),
    )

    with pytest.raises(exception_type) as exc_info:
        transport.get_me()

    if reason is not None:
        assert exc_info.value.reason == reason


def test_fetch_profile_parses_embedded_profile_payload(monkeypatch) -> None:
    config = load_config()
    jar = RequestsCookieJar()
    jar.set("JSESSIONID", '"ajax:123"', domain=".linkedin.com", path="/")
    session = AuthSession(cookie_jar=jar, source="env")
    transport = LinkedInVoyagerTransport(session, config)
    body = {
        "data": {
            "data": {
                "identityDashProfilesByMemberIdentity": {"*elements": ["urn:li:fsd_profile:123"]}
            }
        },
        "included": [
            {
                "$type": "com.linkedin.voyager.dash.common.Geo",
                "entityUrn": "urn:li:fsd_geo:1",
                "defaultLocalizedNameWithoutCountryName": "Buenos Aires",
                "defaultLocalizedName": "Buenos Aires, Argentina",
            },
            {
                "$type": "com.linkedin.voyager.dash.identity.profile.Profile",
                "entityUrn": "urn:li:fsd_profile:123",
                "publicIdentifier": "jane-doe",
                "firstName": "Jane",
                "lastName": "Doe",
                "headline": "Builder",
                "premium": True,
                "creator": False,
                "geoLocation": {"*geo": "urn:li:fsd_geo:1"},
                "profilePicture": {
                    "displayImageReferenceResolutionResult": {
                        "vectorImage": {
                            "rootUrl": "https://media.licdn.com/dms/image/v2/",
                            "artifacts": [
                                {"width": 100, "fileIdentifyingUrlPathSegment": "small.jpg"},
                                {"width": 400, "fileIdentifyingUrlPathSegment": "large.jpg"},
                            ],
                        }
                    }
                },
            },
        ],
    }
    html = (
        "<html><body>"
        '<code id="datalet-bpr-guid-1">'
        + json.dumps(
            {
                "request": (
                    "/voyager/api/graphql?includeWebMetadata=true&variables="
                    "(vanityName:jane-doe)&queryId=voyagerIdentityDashProfiles.hash"
                ),
                "status": 200,
                "body": "bpr-guid-1",
                "method": "GET",
            }
        )
        + "</code>"
        + '<code id="bpr-guid-1">'
        + json.dumps(body)
        + "</code>"
        + "</body></html>"
    )

    monkeypatch.setattr(
        transport,
        "_request_profile_page",
        lambda public_id: _html_response("https://www.linkedin.com/in/jane-doe/", html),
    )

    payload = transport.fetch_profile("jane-doe")

    assert payload["publicIdentifier"] == "jane-doe"
    assert payload["firstName"] == "Jane"
    assert payload["lastName"] == "Doe"
    assert payload["geoLocationName"] == "Buenos Aires"
    assert payload["publicProfileUrl"] == "https://www.linkedin.com/in/jane-doe/"
    assert payload["displayPictureUrl"] == "https://media.licdn.com/dms/image/v2/large.jpg"
