"""Static checks for the auditable Railway authentication-gate deployment."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_dockerfile_uses_locked_install_and_single_factory_worker() -> None:
    dockerfile = _read("Dockerfile")

    assert re.search(r"^FROM ghcr\.io/astral-sh/uv:\d+\.\d+\.\d+-", dockerfile, re.MULTILINE)
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile
    assert "linkedin_cli.web:create_app" in dockerfile
    assert "--factory" in dockerfile
    assert "--workers 1" in dockerfile
    assert "${PORT:-8000}" in dockerfile
    assert "DATABASE_PATH=/app/data/linkedin_finder.sqlite3" in dockerfile


def test_docker_build_context_excludes_private_runtime_material() -> None:
    dockerfile = _read("Dockerfile")
    dockerignore = _read(".dockerignore")

    assert "COPY . " not in dockerfile
    for pattern in (".env", "data/", "*.sqlite3", "*.key", "extension/*.zip"):
        assert pattern in dockerignore

    secret_assignments = (
        "APP_ACCESS_PASSWORD_HASH=",
        "APP_SESSION_SECRET=",
        "COOKIE_ENCRYPTION_KEY=",
        "MCP_BEARER_TOKEN=",
        "OPENROUTER_API_KEY=",
    )
    assert not any(assignment in dockerfile for assignment in secret_assignments)


def test_railway_uses_docker_healthcheck_and_one_factory_worker() -> None:
    config = _read("railway.toml")

    assert 'builder = "DOCKERFILE"' in config
    assert 'dockerfilePath = "Dockerfile"' in config
    assert 'healthcheckPath = "/healthz"' in config
    assert "linkedin_cli.web:create_app" in config
    assert "--factory" in config
    assert "--workers 1" in config
    assert "$PORT" in config
    assert "preDeployCommand" not in config


def test_runbook_defines_volume_readiness_and_strict_gate() -> None:
    runbook = _read("docs/deployment.md")
    normalized = " ".join(runbook.split())

    for required in (
        "/app/data/linkedin_finder.sqlite3",
        "/app/data/reproduction.txt",
        "/healthz",
        "/readyz",
        "Daily backups",
        "at least 24 hours apart",
        "friend's own LinkedIn profile",
        "Immediate stop rule",
        "401",
        "403",
        "429",
        "APP_COMMIT_SHA",
        "one encrypted-session ID",
        "two LinkedIn reads",
        "three failed attempts total",
    ):
        assert required in normalized

    assert "Do not add a build-time or Railway pre-deploy migration command" in normalized
