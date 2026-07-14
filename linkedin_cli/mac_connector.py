"""Build token-bound macOS connector downloads entirely in memory."""

from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED
from zipfile import ZipFile
from zipfile import ZipInfo

from . import mac_connector_runtime


CONNECTOR_FILENAME = "Connect LinkedIn.command"


def build_connector_zip(
    *,
    api_base: str,
    pairing_id: str,
    pairing_token: str,
    connector_commit: str,
) -> bytes:
    """Return one executable command file without touching server storage."""
    runtime_path = Path(mac_connector_runtime.__file__)
    runtime_source = runtime_path.read_text(encoding="utf-8")
    if "\nPY\n" in runtime_source:
        raise RuntimeError("Connector runtime conflicts with its shell heredoc marker.")
    config = json.dumps(
        {
            "api_base": api_base,
            "connector_commit": connector_commit,
            "pairing_id": pairing_id,
            "pairing_token": pairing_token,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    command = (
        "#!/bin/zsh\n"
        "set -u\n"
        "cleanup() {\n"
        "  rm -f -- \"$0\"\n"
        "}\n"
        "trap cleanup EXIT\n"
        "PYTHON_BIN=\"$(command -v python3 2>/dev/null || true)\"\n"
        "if [[ -z \"$PYTHON_BIN\" ]]; then\n"
        "  echo \"Python 3 is required to run this one-time connector.\"\n"
        "  echo \"Install it from https://www.python.org/downloads/macos/ and download a fresh connector.\"\n"
        "  open \"https://www.python.org/downloads/macos/\"\n"
        "  read -r \"?Press Return to close. \"\n"
        "  exit 1\n"
        "fi\n"
        "\"$PYTHON_BIN\" - <<'PY'\n"
        f"{runtime_source.rstrip()}\n\n"
        f"CONNECTOR_CONFIG = {config}\n"
        "raise SystemExit(run_connector(CONNECTOR_CONFIG))\n"
        "PY\n"
        "STATUS=$?\n"
        "if [[ $STATUS -ne 0 ]]; then\n"
        "  read -r \"?Press Return to close. \"\n"
        "fi\n"
        "exit $STATUS\n"
    ).encode("utf-8")

    archive_buffer = BytesIO()
    info = ZipInfo(CONNECTOR_FILENAME, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o100755 << 16
    with ZipFile(archive_buffer, mode="w") as archive:
        archive.writestr(info, command)
    return archive_buffer.getvalue()

