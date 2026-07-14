from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
from pathlib import Path
import sqlite3

from linkedin_cli.storage import Database


COMMIT_SHA = "a" * 40
EXTRACTOR_VERSION = "feasibility-gate-1"


def _database(tmp_path: Path) -> Database:
    database = Database(tmp_path / "gate.sqlite3")
    database.initialize()
    return database


def _iso(offset: timedelta = timedelta()) -> str:
    return (datetime.now(timezone.utc) + offset).isoformat()


def test_initialize_is_idempotent_and_enables_required_settings(tmp_path: Path) -> None:
    database = Database(tmp_path / "nested" / "gate.sqlite3")

    assert database.ready() is False
    database.initialize()
    database.initialize()

    with sqlite3.connect(database.path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [1, 2]
        strict_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM pragma_table_list WHERE strict = 1"
            ).fetchall()
        }
    assert {
        "schema_migrations",
        "users",
        "pairing_tokens",
        "linkedin_sessions",
        "auth_probes",
        "feasibility_gate",
    } <= strict_tables
    assert database.ready() is True

    with database._connect() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5_000
        assert connection.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_v2_migration_preserves_v1_rows_and_creates_gate_tombstone(tmp_path: Path) -> None:
    database = Database(tmp_path / "v1.sqlite3")
    created_at = _iso(timedelta(days=-1))
    with database._connect() as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            ) STRICT
            """
        )
        Database._apply_gate_schema(connection)
        connection.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)",
            (created_at,),
        )
        connection.execute(
            "INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)",
            ("friend", created_at, created_at),
        )
        connection.execute(
            """
            INSERT INTO auth_probes (
                id, user_id, status, kind, public_id, full_name, detail, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-rejection",
                "friend",
                "rejected",
                "checkpoint",
                "",
                "",
                "",
                created_at,
            ),
        )

    database.initialize()
    database.initialize()

    with database._connect() as connection:
        versions = [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
        user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        probe_columns = {row[1] for row in connection.execute("PRAGMA table_info(auth_probes)")}
    assert versions == [1, 2]
    assert "session_generation" in user_columns
    assert {
        "linkedin_session_id",
        "deployment_id",
        "commit_sha",
        "extractor_version",
    } <= probe_columns
    generation = database.get_session_generation("friend")
    assert generation
    assert len(generation) == 32
    legacy_probe = database.list_auth_probes("friend")[0]
    assert legacy_probe["linkedin_session_id"] == ""
    assert legacy_probe["deployment_id"] == ""
    assert legacy_probe["commit_sha"] == ""
    assert legacy_probe["extractor_version"] == ""
    assert database.get_gate_control()["state"] == "rejected"
    assert database.get_gate_control()["reason"] == "checkpoint"
    assert database.ready() is True


def test_session_generation_is_stable_until_rotated_or_user_deleted(tmp_path: Path) -> None:
    database = _database(tmp_path)

    database.ensure_user("friend")
    first = database.get_session_generation("friend")
    database.ensure_user("friend")

    assert first
    assert database.get_session_generation("friend") == first
    rotated = database.rotate_session_generation("friend")
    assert rotated
    assert rotated != first
    assert database.get_session_generation("friend") == rotated
    assert database.rotate_session_generation("missing-user") is None
    assert database.delete_user_data("friend") is True
    assert database.get_session_generation("friend") is None


def test_pairing_token_rejects_wrong_expired_and_reused_tokens(tmp_path: Path) -> None:
    database = _database(tmp_path)
    now = _iso()
    valid_id = database.create_pairing_token("friend", "valid-hash", _iso(timedelta(minutes=10)))

    assert database.consume_pairing_token(valid_id, "wrong-hash", now) is None
    assert database.consume_pairing_token(valid_id, "valid-hash", now) == "friend"
    assert database.consume_pairing_token(valid_id, "valid-hash", now) is None

    expired_id = database.create_pairing_token(
        "friend", "expired-hash", _iso(timedelta(seconds=-1))
    )
    assert database.consume_pairing_token(expired_id, "expired-hash", now) is None


def test_pairing_status_is_owner_scoped_and_never_returns_token_hash(tmp_path: Path) -> None:
    database = _database(tmp_path)
    pairing_id = database.create_pairing_token(
        "friend", "must-not-be-returned", _iso(timedelta(minutes=10))
    )

    status = database.get_pairing_token(pairing_id, "friend")

    assert status is not None
    assert status["id"] == pairing_id
    assert status["consumed_at"] is None
    assert "token_hash" not in status
    assert database.get_pairing_token(pairing_id, "someone-else") is None


def test_session_persists_only_encrypted_payload_and_cookie_names(tmp_path: Path) -> None:
    database = _database(tmp_path)
    secret_cookie_value = "AQED-secret-cookie-value"
    ciphertext = b"encrypted-ciphertext"

    session_id = database.save_linkedin_session(
        "friend",
        ciphertext,
        b"012345678901",
        b"friend:pairing-id",
        ["li_at", "JSESSIONID", "li_at"],
    )

    session = database.get_active_linkedin_session("friend")
    assert session is not None
    assert session["id"] == session_id
    assert session["ciphertext"] == ciphertext
    assert session["cookie_names"] == ["JSESSIONID", "li_at"]

    persisted = database.path.read_bytes()
    assert secret_cookie_value.encode() not in persisted
    assert b"encrypted-ciphertext" in persisted
    with sqlite3.connect(database.path) as connection:
        row = connection.execute(
            "SELECT typeof(ciphertext), typeof(nonce), typeof(aad), cookie_names "
            "FROM linkedin_sessions"
        ).fetchone()
    assert row[:3] == ("blob", "blob", "blob")
    assert json.loads(row[3]) == ["JSESSIONID", "li_at"]


def test_session_save_replaces_prior_session_and_delete_removes_it(tmp_path: Path) -> None:
    database = _database(tmp_path)
    first_id = database.save_linkedin_session("friend", b"first", b"first-nonce", b"aad", ["li_at"])
    second_id = database.save_linkedin_session(
        "friend", b"second", b"second-nonce", b"aad", ["JSESSIONID"]
    )

    assert first_id != second_id
    session = database.get_active_linkedin_session("friend")
    assert session is not None
    assert session["id"] == second_id
    assert session["ciphertext"] == b"second"
    with sqlite3.connect(database.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM linkedin_sessions").fetchone()[0] == 1

    assert database.delete_linkedin_session("friend") is True
    assert database.delete_linkedin_session("friend") is False
    assert database.get_active_linkedin_session("friend") is None


def test_expired_session_is_not_active(tmp_path: Path) -> None:
    database = _database(tmp_path)
    database.save_linkedin_session(
        "friend",
        b"ciphertext",
        b"nonce",
        b"aad",
        ["li_at"],
        expires_at=_iso(timedelta(seconds=-1)),
    )

    assert database.get_active_linkedin_session("friend") is None


def test_probe_history_is_returned_in_recorded_order(tmp_path: Path) -> None:
    database = _database(tmp_path)
    first_id = database.record_auth_probe(
        "friend",
        "passed",
        "profile-read",
        linkedin_session_id="linkedin-session-one",
        deployment_id="deployment-one",
        commit_sha=COMMIT_SHA,
        extractor_version=EXTRACTOR_VERSION,
        public_id="ada-lovelace",
        full_name="Ada Lovelace",
    )
    second_id = database.record_auth_probe(
        "friend",
        "rejected",
        "checkpoint",
        linkedin_session_id="linkedin-session-one",
        deployment_id="deployment-two",
        commit_sha=COMMIT_SHA,
        extractor_version=EXTRACTOR_VERSION,
        detail="LinkedIn requested a challenge",
    )

    probes = database.list_auth_probes("friend")

    assert [probe["id"] for probe in probes] == [first_id, second_id]
    assert probes[0]["public_id"] == "ada-lovelace"
    assert probes[0]["linkedin_session_id"] == "linkedin-session-one"
    assert probes[0]["deployment_id"] == "deployment-one"
    assert probes[0]["commit_sha"] == COMMIT_SHA
    assert probes[0]["extractor_version"] == EXTRACTOR_VERSION
    assert probes[1]["status"] == "rejected"
    assert probes[1]["deployment_id"] == "deployment-two"
    assert probes[1]["detail"] == "LinkedIn requested a challenge"


def test_gate_control_exhausts_after_three_total_transient_failures(tmp_path: Path) -> None:
    database = _database(tmp_path)

    first = database.record_transient_gate_failure(maximum=3)
    second = database.record_transient_gate_failure(maximum=3)
    third = database.record_transient_gate_failure(maximum=3)

    assert first["state"] == "open"
    assert first["transient_failures"] == 1
    assert second["state"] == "open"
    assert second["transient_failures"] == 2
    assert third["state"] == "retry_exhausted"
    assert third["transient_failures"] == 3
    assert third["reason"] == "transient-retry-limit"


def test_gate_tombstone_survives_user_deletion_and_database_restart(tmp_path: Path) -> None:
    database = _database(tmp_path)
    database.ensure_user("friend")
    database.stop_gate("checkpoint")

    assert database.delete_user_data("friend") is True
    reopened = Database(database.path)
    reopened.initialize()

    control = reopened.get_gate_control()
    assert control["state"] == "rejected"
    assert control["reason"] == "checkpoint"
    assert reopened.get_session_generation("friend") is None


def test_secure_delete_and_checkpoint_remove_deleted_session_bytes(tmp_path: Path) -> None:
    database = _database(tmp_path)
    marker = b"UNIQUE-ENCRYPTED-SESSION-MARKER-DO-NOT-RETAIN"
    profile_marker = "UNIQUE-PROFILE-NAME-MARKER-DO-NOT-RETAIN"
    session_id = database.save_linkedin_session(
        "friend",
        marker,
        b"nonce",
        b"aad",
        ["li_at", "JSESSIONID"],
    )
    database.record_auth_probe(
        "friend",
        "passed",
        "profile-read",
        linkedin_session_id=session_id,
        deployment_id="deployment-one",
        commit_sha=COMMIT_SHA,
        extractor_version=EXTRACTOR_VERSION,
        full_name=profile_marker,
    )
    assert marker in database.path.read_bytes()
    assert profile_marker.encode() in database.path.read_bytes()

    assert database.delete_user_data("friend") is True

    for sqlite_file in tmp_path.glob("gate.sqlite3*"):
        assert marker not in sqlite_file.read_bytes()
        assert profile_marker.encode() not in sqlite_file.read_bytes()


def test_delete_user_data_cascades_to_all_gate_records(tmp_path: Path) -> None:
    database = _database(tmp_path)
    database.ensure_user("friend")
    database.create_pairing_token("friend", "token-hash", _iso(timedelta(minutes=10)))
    linkedin_session_id = database.save_linkedin_session(
        "friend", b"ciphertext", b"nonce", b"aad", ["li_at", "JSESSIONID"]
    )
    database.record_auth_probe(
        "friend",
        "passed",
        "profile-read",
        linkedin_session_id=linkedin_session_id,
        deployment_id="deployment-one",
        commit_sha=COMMIT_SHA,
        extractor_version=EXTRACTOR_VERSION,
    )

    assert database.delete_user_data("friend") is True
    assert database.delete_user_data("friend") is False
    assert database.get_active_linkedin_session("friend") is None
    assert database.list_auth_probes("friend") == []

    with sqlite3.connect(database.path) as connection:
        for table in ("users", "pairing_tokens", "linkedin_sessions", "auth_probes"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM feasibility_gate").fetchone()[0] == 1


def test_completed_gate_is_terminal_and_survives_user_deletion(tmp_path: Path) -> None:
    database = _database(tmp_path)
    database.ensure_user("friend")

    assert database.complete_gate() is True
    assert database.complete_gate() is False
    control = database.get_gate_control()
    assert control["state"] == "passed"
    assert control["reason"] == "three-probe-proof"

    assert database.delete_user_data("friend") is True
    database.initialize()
    assert database.get_gate_control()["state"] == "passed"
