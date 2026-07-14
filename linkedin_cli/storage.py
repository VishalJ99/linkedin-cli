"""SQLite persistence for the Railway authentication feasibility gate."""

from __future__ import annotations

from datetime import datetime
from datetime import timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
from typing import Iterable
from uuid import uuid4


_BUSY_TIMEOUT_MS = 5_000
_COOKIE_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REQUIRED_TABLES = {
    "schema_migrations",
    "users",
    "pairing_tokens",
    "linkedin_sessions",
    "auth_probes",
    "feasibility_gate",
}


def _utc_iso(value: datetime | str | None = None) -> str:
    """Return a normalized, lexically sortable UTC ISO-8601 timestamp."""
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    else:
        raise TypeError("Timestamp must be a datetime or ISO-8601 string.")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _blob(value: bytes | bytearray | memoryview, field_name: str) -> sqlite3.Binary:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{field_name} must be bytes-like.")
    return sqlite3.Binary(bytes(value))


def _cookie_names_json(cookie_names: Iterable[str]) -> str:
    names = []
    for name in cookie_names:
        if not isinstance(name, str) or not _COOKIE_NAME_PATTERN.fullmatch(name):
            raise ValueError(f"Invalid cookie name: {name!r}")
        names.append(name)
    return json.dumps(sorted(set(names)), separators=(",", ":"))


class Database:
    """Small SQLite repository for encrypted LinkedIn session gate data."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            str(self.path),
            timeout=_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA secure_delete = ON")
        return connection

    def initialize(self) -> None:
        """Create or migrate the gate schema; safe to call on every startup."""
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                ) STRICT
                """
            )
            applied = {
                row["version"]
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            if 1 not in applied:
                self._apply_gate_schema(connection)
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (1, _utc_iso()),
                )
            if 2 not in applied:
                self._apply_gate_control_migration(connection)
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (2, _utc_iso()),
                )

    @staticmethod
    def _apply_gate_schema(connection: sqlite3.Connection) -> None:
        statements = (
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            ) STRICT
            """,
            """
            CREATE TABLE pairing_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                created_at TEXT NOT NULL
            ) STRICT
            """,
            """
            CREATE INDEX pairing_tokens_user_id_idx
            ON pairing_tokens (user_id, created_at)
            """,
            """
            CREATE TABLE linkedin_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                aad BLOB NOT NULL,
                cookie_names TEXT NOT NULL
                    CHECK (json_valid(cookie_names) AND json_type(cookie_names) = 'array'),
                expires_at TEXT,
                created_at TEXT NOT NULL
            ) STRICT
            """,
            """
            CREATE TABLE auth_probes (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                kind TEXT NOT NULL,
                public_id TEXT NOT NULL DEFAULT '',
                full_name TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            ) STRICT
            """,
            """
            CREATE INDEX auth_probes_user_id_idx
            ON auth_probes (user_id, created_at, id)
            """,
        )
        for statement in statements:
            connection.execute(statement)

    @staticmethod
    def _apply_gate_control_migration(connection: sqlite3.Connection) -> None:
        user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "session_generation" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN session_generation TEXT NOT NULL DEFAULT ''"
            )
            connection.execute(
                "UPDATE users SET session_generation = lower(hex(randomblob(16))) "
                "WHERE session_generation = ''"
            )

        probe_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(auth_probes)")
        }
        if "linkedin_session_id" not in probe_columns:
            connection.execute(
                "ALTER TABLE auth_probes ADD COLUMN linkedin_session_id TEXT NOT NULL DEFAULT ''"
            )
        if "deployment_id" not in probe_columns:
            connection.execute(
                "ALTER TABLE auth_probes ADD COLUMN deployment_id TEXT NOT NULL DEFAULT ''"
            )
        if "commit_sha" not in probe_columns:
            connection.execute(
                "ALTER TABLE auth_probes ADD COLUMN commit_sha TEXT NOT NULL DEFAULT ''"
            )
        if "extractor_version" not in probe_columns:
            connection.execute(
                "ALTER TABLE auth_probes ADD COLUMN extractor_version TEXT NOT NULL DEFAULT ''"
            )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS feasibility_gate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state TEXT NOT NULL
                    CHECK (state IN ('open', 'passed', 'rejected', 'retry_exhausted')),
                reason TEXT NOT NULL DEFAULT '',
                transient_failures INTEGER NOT NULL DEFAULT 0 CHECK (transient_failures >= 0),
                updated_at TEXT NOT NULL
            ) STRICT
            """
        )
        connection.execute(
            """
            INSERT INTO feasibility_gate (id, state, reason, transient_failures, updated_at)
            VALUES (1, 'open', '', 0, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (_utc_iso(),),
        )
        rejection = connection.execute(
            """
            SELECT kind, created_at
            FROM auth_probes
            WHERE status = 'rejected'
            ORDER BY created_at ASC, id ASC
            LIMIT 1
            """
        ).fetchone()
        if rejection is not None:
            connection.execute(
                """
                UPDATE feasibility_gate
                SET state = 'rejected', reason = ?, updated_at = ?
                WHERE id = 1 AND state = 'open'
                """,
                (rejection["kind"], rejection["created_at"]),
            )

    @staticmethod
    def _ensure_user(connection: sqlite3.Connection, user_id: str) -> None:
        if not user_id:
            raise ValueError("user_id must not be empty.")
        now = _utc_iso()
        connection.execute(
            """
            INSERT INTO users (id, created_at, updated_at, session_generation)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (user_id, now, now, str(uuid4())),
        )

    def ensure_user(self, user_id: str = "friend") -> str:
        with self._connect() as connection:
            self._ensure_user(connection, user_id)
        return user_id

    def get_session_generation(self, user_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT session_generation FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return str(row["session_generation"]) if row is not None else None

    def rotate_session_generation(self, user_id: str) -> str | None:
        generation = str(uuid4())
        with self._connect() as connection:
            updated = connection.execute(
                """
                UPDATE users
                SET session_generation = ?, updated_at = ?
                WHERE id = ?
                """,
                (generation, _utc_iso(), user_id),
            )
        return generation if updated.rowcount == 1 else None

    def create_pairing_token(
        self,
        user_id: str,
        token_hash: str,
        expires_at: datetime | str,
    ) -> str:
        if not token_hash:
            raise ValueError("token_hash must not be empty.")
        pairing_id = str(uuid4())
        with self._connect() as connection:
            self._ensure_user(connection, user_id)
            connection.execute(
                """
                INSERT INTO pairing_tokens (
                    id, user_id, token_hash, expires_at, consumed_at, created_at
                ) VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (pairing_id, user_id, token_hash, _utc_iso(expires_at), _utc_iso()),
            )
        return pairing_id

    def consume_pairing_token(
        self,
        pairing_id: str,
        token_hash: str,
        now: datetime | str,
    ) -> str | None:
        """Consume a matching, unexpired token exactly once in one write transaction."""
        consumed_at = _utc_iso(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT user_id
                FROM pairing_tokens
                WHERE id = ?
                  AND token_hash = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                """,
                (pairing_id, token_hash, consumed_at),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            updated = connection.execute(
                """
                UPDATE pairing_tokens
                SET consumed_at = ?
                WHERE id = ? AND consumed_at IS NULL
                """,
                (consumed_at, pairing_id),
            )
            if updated.rowcount != 1:
                connection.rollback()
                return None
            connection.commit()
            return str(row["user_id"])
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_pairing_token(self, pairing_id: str, user_id: str) -> dict[str, Any] | None:
        """Return non-secret pairing state for its authenticated owner."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, user_id, expires_at, consumed_at, created_at
                FROM pairing_tokens
                WHERE id = ? AND user_id = ?
                """,
                (pairing_id, user_id),
            ).fetchone()
        return dict(row) if row is not None else None

    def save_linkedin_session(
        self,
        user_id: str,
        ciphertext: bytes | bytearray | memoryview,
        nonce: bytes | bytearray | memoryview,
        aad: bytes | bytearray | memoryview,
        cookie_names: Iterable[str],
        expires_at: datetime | str | None = None,
    ) -> str:
        session_id = str(uuid4())
        with self._connect() as connection:
            self._ensure_user(connection, user_id)
            connection.execute("DELETE FROM linkedin_sessions WHERE user_id = ?", (user_id,))
            connection.execute(
                """
                INSERT INTO linkedin_sessions (
                    id, user_id, ciphertext, nonce, aad, cookie_names, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    _blob(ciphertext, "ciphertext"),
                    _blob(nonce, "nonce"),
                    _blob(aad, "aad"),
                    _cookie_names_json(cookie_names),
                    _utc_iso(expires_at) if expires_at is not None else None,
                    _utc_iso(),
                ),
            )
        return session_id

    def get_active_linkedin_session(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, user_id, ciphertext, nonce, aad, cookie_names, expires_at, created_at
                FROM linkedin_sessions
                WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)
                """,
                (user_id, _utc_iso()),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["ciphertext"] = bytes(result["ciphertext"])
        result["nonce"] = bytes(result["nonce"])
        result["aad"] = bytes(result["aad"])
        result["cookie_names"] = json.loads(result["cookie_names"])
        return result

    def delete_linkedin_session(self, user_id: str) -> bool:
        with self._connect() as connection:
            deleted = connection.execute(
                "DELETE FROM linkedin_sessions WHERE user_id = ?", (user_id,)
            )
        return deleted.rowcount > 0

    def record_auth_probe(
        self,
        user_id: str,
        status: str,
        kind: str,
        *,
        linkedin_session_id: str,
        deployment_id: str,
        commit_sha: str,
        extractor_version: str,
        public_id: str = "",
        full_name: str = "",
        detail: str = "",
    ) -> str:
        if not all(
            (
                status,
                kind,
                linkedin_session_id,
                deployment_id,
                commit_sha,
                extractor_version,
            )
        ):
            raise ValueError(
                "Probe classification, session, deployment, commit, and extractor must not "
                "be empty."
            )
        probe_id = str(uuid4())
        with self._connect() as connection:
            self._ensure_user(connection, user_id)
            connection.execute(
                """
                INSERT INTO auth_probes (
                    id, user_id, status, kind, public_id, full_name, detail, created_at,
                    linkedin_session_id, deployment_id, commit_sha, extractor_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    probe_id,
                    user_id,
                    status,
                    kind,
                    public_id,
                    full_name,
                    detail,
                    _utc_iso(),
                    linkedin_session_id,
                    deployment_id,
                    commit_sha,
                    extractor_version,
                ),
            )
        return probe_id

    def list_auth_probes(self, user_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, user_id, status, kind, public_id, full_name, detail, created_at,
                       linkedin_session_id, deployment_id, commit_sha, extractor_version
                FROM auth_probes
                WHERE user_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_gate_control(self) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT state, reason, transient_failures, updated_at
                FROM feasibility_gate
                WHERE id = 1
                """
            ).fetchone()
        if row is None:
            raise RuntimeError("Feasibility gate control row is missing.")
        return dict(row)

    def stop_gate(self, reason: str) -> None:
        if not reason:
            raise ValueError("Gate stop reason must not be empty.")
        with self._connect() as connection:
            updated_at = _utc_iso()
            connection.execute(
                """
                UPDATE feasibility_gate
                SET state = 'rejected', reason = ?, updated_at = ?
                WHERE id = 1
                """,
                (reason, updated_at),
            )

    def complete_gate(self, reason: str = "three-probe-proof") -> bool:
        if not reason:
            raise ValueError("Gate completion reason must not be empty.")
        with self._connect() as connection:
            updated = connection.execute(
                """
                UPDATE feasibility_gate
                SET state = 'passed', reason = ?, updated_at = ?
                WHERE id = 1 AND state = 'open'
                """,
                (reason, _utc_iso()),
            )
        return updated.rowcount == 1

    def record_transient_gate_failure(self, *, maximum: int) -> dict[str, Any]:
        if maximum < 1:
            raise ValueError("maximum must be positive.")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state, transient_failures FROM feasibility_gate WHERE id = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("Feasibility gate control row is missing.")
            failures = int(row["transient_failures"]) + 1
            state = str(row["state"])
            if state == "open" and failures >= maximum:
                state = "retry_exhausted"
            updated_at = _utc_iso()
            connection.execute(
                """
                UPDATE feasibility_gate
                SET state = ?, reason = ?, transient_failures = ?, updated_at = ?
                WHERE id = 1
                """,
                (
                    state,
                    "transient-retry-limit" if state == "retry_exhausted" else "",
                    failures,
                    updated_at,
                ),
            )
            result = {
                "state": state,
                "reason": "transient-retry-limit" if state == "retry_exhausted" else "",
                "transient_failures": failures,
                "updated_at": updated_at,
            }
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def delete_user_data(self, user_id: str) -> bool:
        connection = self._connect()
        try:
            deleted = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return deleted.rowcount > 0
        finally:
            connection.close()

    def ready(self) -> bool:
        """Return whether the initialized schema is queryable with required settings."""
        if not self.path.exists():
            return False
        try:
            with self._connect() as connection:
                table_names = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
                busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                secure_delete = connection.execute("PRAGMA secure_delete").fetchone()[0]
                quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
            return (
                _REQUIRED_TABLES <= table_names
                and foreign_keys == 1
                and busy_timeout >= _BUSY_TIMEOUT_MS
                and str(journal_mode).lower() == "wal"
                and secure_delete == 1
                and quick_check == "ok"
            )
        except sqlite3.Error:
            return False
