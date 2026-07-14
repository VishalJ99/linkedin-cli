from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import textwrap

import pytest


ROOT = Path(__file__).parents[1]
EXTENSION = ROOT / "extension"


def _manifest() -> dict:
    return json.loads((EXTENSION / "manifest.json").read_text())


def _javascript() -> str:
    return "\n".join((EXTENSION / name).read_text() for name in ("config.js", "service-worker.js"))


def test_manifest_is_scoped_manifest_v3_connector() -> None:
    manifest = _manifest()

    assert manifest["manifest_version"] == 3
    assert manifest["background"] == {"service_worker": "service-worker.js"}
    assert manifest["permissions"] == []
    assert manifest["optional_permissions"] == ["cookies"]
    assert "host_permissions" not in manifest
    assert "https://*.linkedin.com/*" in manifest["optional_host_permissions"]
    assert "storage" not in manifest["permissions"]
    assert "<all_urls>" not in json.dumps(manifest)
    assert "content_scripts" not in manifest


def test_manifest_public_key_produces_the_documented_stable_extension_id() -> None:
    manifest = _manifest()
    digest = hashlib.sha256(base64.b64decode(manifest["key"])).hexdigest()[:32]
    extension_id = "".join(chr(ord("a") + int(character, 16)) for character in digest)

    assert extension_id == "ohjgceimoldkhlncabhahccapgoolknc"


def test_external_and_optional_origins_are_narrowly_scoped() -> None:
    manifest = _manifest()
    optional_origins = set(manifest["optional_host_permissions"])
    external_origins = set(manifest["externally_connectable"]["matches"])

    assert external_origins == optional_origins - {"https://*.linkedin.com/*"}
    assert optional_origins == {
        "https://*.linkedin.com/*",
        "https://*.up.railway.app/*",
        "https://*.railway.app/*",
    }
    assert all(origin.startswith("https://") for origin in optional_origins)
    production_config = (EXTENSION / "config.js").read_text()
    assert (
        "allowedApiOrigins: Object.freeze([\n"
        '    "https://linkedin-conversation-finder-production.up.railway.app"\n'
        "  ])"
    ) in production_config
    assert "localhost" not in production_config.split("globalThis.", 1)[1]


def test_service_worker_requires_explicit_validated_pairing() -> None:
    source = (EXTENSION / "service-worker.js").read_text()
    handler = source[source.index("async function handlePairing") :]

    assert "chrome.runtime.onMessageExternal.addListener" in source
    assert "chrome.runtime.onMessage.addListener" not in source
    assert 'const MESSAGE_TYPE = "PAIR_LINKEDIN"' in source
    assert 'const READY_MESSAGE_TYPE = "CONNECTOR_READY"' in source
    assert "message.userGesture" not in source
    assert "senderUrl.origin !== apiUrl.origin" in source
    assert "configuredOrigins().includes(apiUrl.origin)" in source
    assert handler.index("validatePairRequest") < handler.index("collectLinkedInCookies")
    assert handler.index("ensureRuntimePermissions") < handler.index("collectLinkedInCookies")
    before_permission_request = handler[: handler.index("await ensureRuntimePermissions")]
    assert "await " not in before_permission_request
    assert 'permissions: ["cookies"]' in source
    assert "chrome.permissions.request(requested)" in source
    assert "chrome.permissions.remove(requested)" in source
    assert "transferInFlight" in source
    assert "startupPermissionCleanup" in source
    assert "revokeResidualPermissionsAtStartup" in source
    permission_function = source[
        source.index("async function ensureRuntimePermissions") : source.index(
            "function cookieIdentity"
        )
    ]
    assert "chrome.permissions.contains" not in permission_function
    website_source = (ROOT / "linkedin_cli" / "static" / "app.js").read_text()
    assert 'type: "CONNECTOR_READY"' in website_source
    assert website_source.index('type: "CONNECTOR_READY"') < website_source.index(
        'type: "PAIR_LINKEDIN"'
    )


def test_service_worker_posts_cookie_jar_once_without_echoing_it() -> None:
    source = (EXTENSION / "service-worker.js").read_text()

    assert '"https://www.linkedin.com/voyager/api/"' in source
    assert "chrome.cookies.getAll({url})" in source
    assert 'Object.freeze(["li_at", "JSESSIONID"])' in source
    assert source.count("fetch(") == 1
    assert "/api/pairings/${pairingId}/complete" in source
    assert "Authorization: `Bearer ${request.token}`" in source
    assert "body: JSON.stringify({cookies})" in source
    assert "response.json" not in source
    assert "cookieCount: cookies.length" in source
    assert "sendResponse({ok: false, error: code})" in source


def test_extension_has_no_monitoring_logging_or_persistence() -> None:
    source = _javascript()

    forbidden = (
        "chrome.storage",
        "localStorage",
        "sessionStorage",
        "cookies.onChanged",
        "setInterval(",
        "chrome.alarms",
        "console.",
    )
    assert not any(value in source for value in forbidden)


def test_popup_has_accessible_instructions_and_live_status() -> None:
    popup = (EXTENSION / "popup.html").read_text()
    styles = (EXTENSION / "popup.css").read_text()

    assert '<html lang="en">' in popup
    assert "<main>" in popup
    assert 'role="status" aria-live="polite"' in popup
    assert "Connect LinkedIn" in popup
    assert "removed immediately afterward" in popup
    assert ":focus-visible" in styles


def test_service_worker_executes_one_synthetic_transfer_and_releases_access() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the extension runtime fixture.")

    source = (EXTENSION / "service-worker.js").read_text()
    runner = textwrap.dedent(
        f"""
        const source = {json.dumps(source)};
        const calls = [];
        let listener;
        let failLinkedinRemoval = false;
        globalThis.importScripts = () => {{
          globalThis.LINKEDIN_CONNECTOR_CONFIG = Object.freeze({{
            allowedApiOrigins: Object.freeze(["http://localhost:8000"])
          }});
        }};
        globalThis.chrome = {{
          runtime: {{
            onMessageExternal: {{
              addListener: (value) => {{ listener = value; }}
            }}
          }},
          permissions: {{
            request: async (value) => {{ calls.push(["request", value]); return true; }},
            remove: async (value) => {{
              calls.push(["remove", value]);
              return !(failLinkedinRemoval && value.permissions?.includes("cookies"));
            }}
          }},
          cookies: {{
            getAll: async (query) => {{
              calls.push(["cookies", query.url]);
              return [
                {{name: "li_at", value: "SYNTHETIC-LI-AT", domain: ".linkedin.com", path: "/", secure: true, httpOnly: true}},
                {{name: "JSESSIONID", value: "SYNTHETIC-JSESSION", domain: ".linkedin.com", path: "/", secure: true, httpOnly: false}}
              ];
            }}
          }}
        }};
        globalThis.fetch = async (url, options) => {{
          calls.push(["fetch", url, options]);
          return {{ok: true, status: 200}};
        }};
        eval(source);

        (async () => {{
          if (typeof listener !== "function") throw new Error("listener_missing");
          const pendingResponse = await new Promise((resolve, reject) => {{
            const keptOpen = listener(
              {{
                type: "PAIR_LINKEDIN",
                pairingId: "pairing_initializing",
                token: "initializingABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
                apiBase: "http://localhost:8000"
              }},
              {{url: "http://localhost:8000/"}},
              resolve
            );
            if (keptOpen !== true) reject(new Error("pending_channel_not_kept_open"));
            setTimeout(() => reject(new Error("pending_response_timeout")), 1000);
          }});
          if (pendingResponse.ok || pendingResponse.error !== "connector_initializing") {{
            throw new Error("pending_cleanup_not_blocked");
          }}
          if (calls.some(([name]) => name === "request")) throw new Error("requested_while_pending");
          const readyResponse = await new Promise((resolve, reject) => {{
            const keptOpen = listener(
              {{type: "CONNECTOR_READY", apiBase: "http://localhost:8000"}},
              {{url: "http://localhost:8000/"}},
              resolve
            );
            if (keptOpen !== true) reject(new Error("ready_channel_not_kept_open"));
            setTimeout(() => reject(new Error("ready_response_timeout")), 1000);
          }});
          if (!readyResponse.ok || readyResponse.ready !== true) throw new Error("connector_not_ready");

          const response = await new Promise((resolve, reject) => {{
            const keptOpen = listener(
              {{
                type: "PAIR_LINKEDIN",
                pairingId: "pairing_123456789",
                token: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
                apiBase: "http://localhost:8000"
              }},
              {{url: "http://localhost:8000/"}},
              resolve
            );
            if (keptOpen !== true) reject(new Error("channel_not_kept_open"));
            setTimeout(() => reject(new Error("response_timeout")), 1000);
          }});
          if (!response.ok || response.status !== 200 || response.cookieCount !== 2) {{
            throw new Error("unsafe_response");
          }}
          if (JSON.stringify(response).includes("SYNTHETIC")) throw new Error("cookie_echo");
          const requestIndex = calls.findIndex(([name]) => name === "request");
          const fetchIndex = calls.findIndex(([name]) => name === "fetch");
          const removeIndexes = calls
            .map(([name], index) => name === "remove" ? index : -1)
            .filter((index) => index >= 0);
          const startupRemoveIndexes = removeIndexes.filter((index) => index < requestIndex);
          const operationRemoveIndexes = removeIndexes.filter((index) => index > requestIndex);
          if (!(startupRemoveIndexes.length === 2 && operationRemoveIndexes[0] > requestIndex && fetchIndex > operationRemoveIndexes[0] && operationRemoveIndexes[1] > fetchIndex)) {{
            throw new Error("unsafe_call_order");
          }}
          if (calls.filter(([name]) => name === "fetch").length !== 1) throw new Error("fetch_count");
          if (operationRemoveIndexes.length !== 2) throw new Error("remove_count");
          const linkedinRemoval = calls[operationRemoveIndexes[0]][1];
          if (linkedinRemoval.permissions[0] !== "cookies" || linkedinRemoval.origins[0] !== "https://*.linkedin.com/*") {{
            throw new Error("linkedin_access_not_removed_first");
          }}
          const apiRemoval = calls[operationRemoveIndexes[1]][1];
          if (apiRemoval.origins[0] !== "http://localhost/*") throw new Error("api_access_not_removed");
          const fetchCall = calls[fetchIndex];
          if (!fetchCall[1].endsWith("/api/pairings/pairing_123456789/complete")) {{
            throw new Error("wrong_endpoint");
          }}
          if (fetchCall[2].headers.Authorization !== "Bearer abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN") {{
            throw new Error("wrong_authorization");
          }}

          failLinkedinRemoval = true;
          const failedResponse = await new Promise((resolve, reject) => {{
            const keptOpen = listener(
              {{
                type: "PAIR_LINKEDIN",
                pairingId: "pairing_987654321",
                token: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
                apiBase: "http://localhost:8000"
              }},
              {{url: "http://localhost:8000/"}},
              resolve
            );
            if (keptOpen !== true) reject(new Error("failure_channel_not_kept_open"));
            setTimeout(() => reject(new Error("failure_response_timeout")), 1000);
          }});
          if (failedResponse.ok || failedResponse.error !== "permission_release_failed") {{
            throw new Error("release_failure_not_reported");
          }}
          if (calls.filter(([name]) => name === "fetch").length !== 1) {{
            throw new Error("uploaded_after_release_failure");
          }}
        }})().catch((error) => {{
          process.stderr.write(String(error && error.stack || error));
          process.exitCode = 1;
        }});
        """
    )
    completed = subprocess.run(
        [node, "-e", runner],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
