# syntax=docker/dockerfile:1

# Pin uv so the lock-file installer does not change underneath a deployment.
FROM ghcr.io/astral-sh/uv:0.9.26-python3.13-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH" \
    DATABASE_PATH=/app/data/linkedin_finder.sqlite3

WORKDIR /app

# Copy only declared build inputs. In particular, never copy local .env or data
# directories into the image.
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY linkedin_cli ./linkedin_cli

RUN uv sync --frozen --no-dev --no-editable \
    && mkdir -p /app/data

EXPOSE 8000

# The app factory initializes/migrates SQLite after Railway mounts /app/data.
# Railway supplies PORT; 8000 is only the local-container fallback.
CMD ["/bin/sh", "-c", "exec uvicorn --factory linkedin_cli.web:create_app --host 0.0.0.0 --port \"${PORT:-8000}\" --workers 1"]
