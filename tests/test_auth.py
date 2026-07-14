from __future__ import annotations

from copy import deepcopy

import pytest

from linkedin_cli.auth import AuthenticationError
from linkedin_cli.auth import auth_session_from_cookie_records
from linkedin_cli.auth import collect_auth_diagnostics
from linkedin_cli.auth import collect_auth_diagnostics_for_session
from linkedin_cli.auth import collect_gate_diagnostics_for_session
from linkedin_cli.auth import probe_read_access
from linkedin_cli.config import load_config


def _cookie_records() -> list[dict[str, object]]:
    return [
        {
            "name": "li_at",
            "value": "li-at-secret",
            "domain": ".linkedin.com",
            "path": "/",
            "secure": True,
            "httpOnly": True,
            "sameSite": "no_restriction",
            "hostOnly": False,
            "session": False,
            "expirationDate": 1_900_000_000.75,
        },
        {
            "name": "JSESSIONID",
            "value": '"ajax:123456"',
            "domain": "WWW.LinkedIn.COM",
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "sameSite": "lax",
            "hostOnly": True,
            "session": True,
            "expirationDate": None,
        },
        {
            "name": "lang",
            "value": "v=2&lang=en-us",
            "domain": ".www.linkedin.com",
            "path": "/voyager",
            "secure": False,
            "httpOnly": False,
            "sameSite": "strict",
            "hostOnly": False,
            "session": False,
            "expirationDate": None,
        },
    ]


def test_auth_session_from_cookie_records_preserves_requests_metadata() -> None:
    records = _cookie_records()
    original = deepcopy(records)

    session = auth_session_from_cookie_records(
        records,
        source="railway-extension",
        proxy="http://proxy.test:8080",
    )

    assert records == original
    assert session.source == "railway-extension"
    assert session.proxy == "http://proxy.test:8080"
    assert session.browser is None
    assert session.cookie_count == 3
    assert session.cookie_names == ["JSESSIONID", "lang", "li_at"]
    assert session.li_at == "li-at-secret"
    assert session.jsessionid == "ajax:123456"

    li_at = session.cookie_jar._find("li_at", domain=".linkedin.com", path="/")
    assert li_at == "li-at-secret"
    li_at_cookie = next(
        cookie
        for cookie in session.cookie_jar
        if cookie.name == "li_at" and cookie.domain == ".linkedin.com"
    )
    assert li_at_cookie.secure is True
    assert li_at_cookie.expires == 1_900_000_000
    assert li_at_cookie.discard is False
    assert li_at_cookie._rest == {"SameSite": "None", "HttpOnly": True}

    jsession_cookie = next(cookie for cookie in session.cookie_jar if cookie.name == "JSESSIONID")
    assert jsession_cookie.domain == "www.linkedin.com"
    assert jsession_cookie.expires is None
    assert jsession_cookie.discard is True
    assert jsession_cookie._rest == {"SameSite": "Lax"}

    lang_cookie = next(cookie for cookie in session.cookie_jar if cookie.name == "lang")
    assert lang_cookie.path == "/voyager"
    assert lang_cookie.secure is False
    assert lang_cookie._rest == {"SameSite": "Strict"}


def test_auth_session_from_cookie_records_allows_linkedin_subdomains() -> None:
    records = _cookie_records()
    records.append(
        {
            "name": "feature_flag",
            "value": "enabled",
            "domain": "static.licdn.linkedin.com",
            "path": "/",
        }
    )

    session = auth_session_from_cookie_records(records)

    assert (
        session.cookie_jar.get(
            "feature_flag",
            domain="static.licdn.linkedin.com",
            path="/",
        )
        == "enabled"
    )


@pytest.mark.parametrize("records", [None, {}, "cookies", (), 42])
def test_auth_session_from_cookie_records_requires_a_list(records) -> None:
    with pytest.raises(AuthenticationError, match="must be a list"):
        auth_session_from_cookie_records(records)


def test_auth_session_from_cookie_records_requires_object_items() -> None:
    with pytest.raises(AuthenticationError, match="record 0 must be an object"):
        auth_session_from_cookie_records(["not-an-object"])


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "linkedin.com.example.com",
        "notlinkedin.com",
        "foo..linkedin.com",
        " linkedin.com",
        "linkedin.com ",
        ".",
        "",
        None,
    ],
)
def test_auth_session_from_cookie_records_rejects_non_linkedin_domains(domain) -> None:
    records = _cookie_records()
    records[0]["domain"] = domain

    with pytest.raises(AuthenticationError, match="domain"):
        auth_session_from_cookie_records(records)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "bad name", "name"),
        ("name", "bad\nname", "name"),
        ("name", 123, "name"),
        ("value", "bad\r\nvalue", "value"),
        ("value", None, "value"),
        ("path", "voyager", "path"),
        ("path", "/bad\x00path", "path"),
        ("secure", "true", "secure"),
        ("httpOnly", 1, "httpOnly"),
        ("hostOnly", "false", "hostOnly"),
        ("session", "false", "session"),
        ("sameSite", "None", "sameSite"),
        ("sameSite", None, "sameSite"),
        ("expirationDate", "1900000000", "expirationDate"),
        ("expirationDate", -1, "expirationDate"),
        ("expirationDate", float("nan"), "expirationDate"),
        ("expirationDate", float("inf"), "expirationDate"),
    ],
)
def test_auth_session_from_cookie_records_validates_cookie_fields(
    field,
    value,
    message,
) -> None:
    records = _cookie_records()
    records[0][field] = value

    with pytest.raises(AuthenticationError, match=message):
        auth_session_from_cookie_records(records)


@pytest.mark.parametrize(
    "records",
    [
        [],
        [
            {
                "name": "li_at",
                "value": "present",
                "domain": ".linkedin.com",
                "path": "/",
            }
        ],
        [
            {
                "name": "li_at",
                "value": "present",
                "domain": ".linkedin.com",
                "path": "/",
            },
            {
                "name": "JSESSIONID",
                "value": '""',
                "domain": ".linkedin.com",
                "path": "/",
            },
        ],
    ],
)
def test_auth_session_from_cookie_records_requires_nonempty_auth_cookies(records) -> None:
    with pytest.raises(AuthenticationError, match="nonempty li_at and JSESSIONID"):
        auth_session_from_cookie_records(records)


def test_auth_session_from_cookie_records_handles_duplicate_required_cookie_names() -> None:
    records = _cookie_records()
    records.insert(
        0,
        {
            "name": "li_at",
            "value": "",
            "domain": "www.linkedin.com",
            "path": "/",
        },
    )

    session = auth_session_from_cookie_records(records)

    assert session.has_required_cookies() is True
    assert session.li_at == "li-at-secret"


def test_auth_session_from_cookie_records_does_not_echo_cookie_values(
    caplog,
    capsys,
) -> None:
    secret = "must-never-appear"
    records = _cookie_records()
    records[0]["value"] = secret
    records[0]["domain"] = "example.com"

    with pytest.raises(AuthenticationError) as error:
        auth_session_from_cookie_records(records)

    captured = capsys.readouterr()
    assert secret not in str(error.value)
    assert secret not in caplog.text
    assert secret not in captured.out
    assert secret not in captured.err


def test_collect_auth_diagnostics_for_explicit_session_skips_resolution(monkeypatch) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())
    observed = {}

    def fail_resolution(_config):
        raise AssertionError("explicit-session diagnostics must not resolve browser or env auth")

    def inspect(current_session, current_config):
        assert current_session is session
        assert current_config is config
        return {
            "ok": True,
            "kind": "profile-read",
            "payload": {
                "firstName": "Jane",
                "lastName": "Doe",
                "miniProfile": {"publicIdentifier": "jane-doe"},
            },
        }

    def probe(current_session, current_config, public_id=None):
        assert current_session is session
        assert current_config is config
        observed["public_id"] = public_id
        return {
            "voyager_me": {"ok": True, "status_code": 200},
            "voyager_feed": {"ok": True, "status_code": 200},
            "voyager_profile": {"ok": True, "status_code": 200},
        }

    monkeypatch.setattr("linkedin_cli.auth.resolve_auth_session", fail_resolution)
    monkeypatch.setattr("linkedin_cli.auth.inspect_auth_session", inspect)
    monkeypatch.setattr("linkedin_cli.auth.probe_read_access", probe)

    diagnostics = collect_auth_diagnostics_for_session(session, config)

    assert diagnostics["ok"] is True
    assert diagnostics["source"] == "extension"
    assert diagnostics["cookie_count"] == 3
    assert diagnostics["cookie_names"] == ["JSESSIONID", "lang", "li_at"]
    assert diagnostics["public_id"] == "jane-doe"
    assert diagnostics["full_name"] == "Jane Doe"
    assert diagnostics["validation"]["kind"] == "profile-read"
    assert diagnostics["hint"] == ""
    assert observed["public_id"] == "jane-doe"
    assert "li-at-secret" not in repr(diagnostics)
    assert "ajax:123456" not in repr(diagnostics)


def test_rejected_validation_prevents_follow_up_read_probes(monkeypatch) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())

    monkeypatch.setattr(
        "linkedin_cli.auth.inspect_auth_session",
        lambda _session, _config: {
            "ok": False,
            "kind": "checkpoint",
            "status_code": 302,
        },
    )

    def fail_probe(*_args, **_kwargs):
        raise AssertionError("a rejected validation must stop before follow-up probes")

    monkeypatch.setattr("linkedin_cli.auth.probe_read_access", fail_probe)

    diagnostics = collect_auth_diagnostics_for_session(session, config)

    assert diagnostics["ok"] is False
    assert diagnostics["validation"]["kind"] == "checkpoint"
    assert diagnostics["probes"] == {}


@pytest.mark.parametrize(
    "stop_result",
    [
        {"ok": False, "reason": "http-error", "status_code": 401},
        {"ok": False, "reason": "http-error", "status_code": 403},
        {"ok": False, "reason": "http-error", "status_code": 429},
        {"ok": False, "reason": "checkpoint", "status_code": 302},
    ],
)
def test_auth_rejection_stops_probe_loop_immediately(monkeypatch, stop_result) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())
    requested_resources = []

    class RejectingTransport:
        def __init__(self, current_session, current_config):
            assert current_session is session
            assert current_config is config

        def probe(self, resource, **_kwargs):
            requested_resources.append(resource)
            return dict(stop_result)

        def probe_profile(self, _public_id):
            raise AssertionError("profile probing must stop after an authentication rejection")

    monkeypatch.setattr("linkedin_cli.transport.LinkedInTransport", RejectingTransport)

    probes = probe_read_access(session, config, public_id="jane-doe")

    assert requested_resources == ["/me"]
    assert probes == {"voyager_me": stop_result}


def test_missing_public_id_cannot_pass_and_records_profile_evidence(monkeypatch) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())
    requested_resources = []

    monkeypatch.setattr(
        "linkedin_cli.auth.inspect_auth_session",
        lambda _session, _config: {
            "ok": True,
            "kind": "profile-read",
            "payload": {"firstName": "Jane", "lastName": "Doe"},
        },
    )

    class SuccessfulTransport:
        def __init__(self, current_session, current_config):
            assert current_session is session
            assert current_config is config

        def probe(self, resource, **_kwargs):
            requested_resources.append(resource)
            return {"ok": True, "status_code": 200}

        def probe_profile(self, _public_id):
            raise AssertionError("a profile request cannot run without a public identifier")

    monkeypatch.setattr("linkedin_cli.transport.LinkedInTransport", SuccessfulTransport)

    diagnostics = collect_auth_diagnostics_for_session(session, config)

    assert diagnostics["ok"] is False
    assert diagnostics["public_id"] == ""
    assert requested_resources == ["/me", "/feed/updatesV2"]
    assert diagnostics["probes"]["voyager_profile"] == {
        "ok": False,
        "kind": "missing-public-id",
        "error": "Authenticated profile did not include a public identifier.",
    }


def test_gate_diagnostics_make_only_auth_and_own_profile_reads(monkeypatch) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())
    profile_reads = []

    monkeypatch.setattr(
        "linkedin_cli.auth.inspect_auth_session",
        lambda current_session, current_config: {
            "ok": current_session is session and current_config is config,
            "kind": "profile-read",
            "status_code": 200,
            "payload": {
                "firstName": "Jane",
                "lastName": "Doe",
                "miniProfile": {"publicIdentifier": "jane-doe"},
            },
        },
    )

    class ProfileOnlyTransport:
        def __init__(self, current_session, current_config):
            assert current_session is session
            assert current_config is config

        def probe_profile(self, public_id):
            profile_reads.append(public_id)
            return {"ok": True, "kind": "profile-read", "status_code": 200}

        def probe(self, *_args, **_kwargs):
            raise AssertionError("gate diagnostics must not repeat /me or fetch feed")

    monkeypatch.setattr("linkedin_cli.transport.LinkedInTransport", ProfileOnlyTransport)

    diagnostics = collect_gate_diagnostics_for_session(session, config)

    assert diagnostics["ok"] is True
    assert profile_reads == ["jane-doe"]
    assert set(diagnostics["probes"]) == {"voyager_profile"}


def test_gate_diagnostics_fail_closed_on_drifted_identity_schema(monkeypatch) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())
    monkeypatch.setattr(
        "linkedin_cli.auth.inspect_auth_session",
        lambda *_args: {
            "ok": True,
            "kind": "profile-read",
            "status_code": 200,
            "payload": {
                "firstName": {"localized": "Jane"},
                "lastName": ["Doe"],
                "miniProfile": "schema-drift",
            },
        },
    )

    diagnostics = collect_gate_diagnostics_for_session(session, config)

    assert diagnostics["ok"] is False
    assert diagnostics["public_id"] == ""
    assert diagnostics["full_name"] == ""
    assert diagnostics["probes"]["voyager_profile"]["kind"] == "missing-public-id"


def test_collect_auth_diagnostics_delegates_resolved_session(monkeypatch) -> None:
    config = load_config()
    session = auth_session_from_cookie_records(_cookie_records())
    expected = {"ok": True, "source": "delegated"}

    monkeypatch.setattr("linkedin_cli.auth.resolve_auth_session", lambda current: session)

    def collect(current_session, current_config):
        assert current_session is session
        assert current_config is config
        return expected

    monkeypatch.setattr("linkedin_cli.auth.collect_auth_diagnostics_for_session", collect)

    assert collect_auth_diagnostics(config) is expected
