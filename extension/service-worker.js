importScripts("config.js");

const MESSAGE_TYPE = "PAIR_LINKEDIN";
const READY_MESSAGE_TYPE = "CONNECTOR_READY";
const LINKEDIN_COOKIE_URLS = Object.freeze([
  "https://www.linkedin.com/",
  "https://www.linkedin.com/feed/",
  "https://www.linkedin.com/voyager/api/"
]);
const REQUIRED_COOKIE_NAMES = Object.freeze(["li_at", "JSESSIONID"]);
const LINKEDIN_PERMISSION_PATTERN = "https://*.linkedin.com/*";
const SAFE_PAIRING_ID = /^[A-Za-z0-9_-]{16,128}$/;
const SAFE_PAIRING_TOKEN = /^[A-Za-z0-9_-]{32,512}$/;
let transferInFlight = false;

class ConnectorError extends Error {
  constructor(code) {
    super(code);
    this.name = "ConnectorError";
    this.code = code;
  }
}

function configuredOrigins() {
  const origins = globalThis.LINKEDIN_CONNECTOR_CONFIG?.allowedApiOrigins;
  if (!Array.isArray(origins) || origins.length === 0) {
    throw new ConnectorError("connector_not_configured");
  }
  return origins;
}

function parseOrigin(value, errorCode) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConnectorError(errorCode);
  }

  const isLoopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(isLoopback && url.protocol === "http:")) {
    throw new ConnectorError(errorCode);
  }
  if (url.username || url.password) {
    throw new ConnectorError(errorCode);
  }
  return url;
}

function validateConfiguredOrigin(message, sender) {
  if (!sender?.url || sender.id) {
    throw new ConnectorError("invalid_sender");
  }

  const senderUrl = parseOrigin(sender.url, "invalid_sender");
  const apiUrl = parseOrigin(message.apiBase, "invalid_api_base");
  if (apiUrl.pathname !== "/" || apiUrl.search || apiUrl.hash) {
    throw new ConnectorError("invalid_api_base");
  }
  if (senderUrl.origin !== apiUrl.origin) {
    throw new ConnectorError("origin_mismatch");
  }
  if (!configuredOrigins().includes(apiUrl.origin)) {
    throw new ConnectorError("origin_not_allowed");
  }

  return apiUrl.origin;
}

function validatePairRequest(message, sender) {
  if (!message || message.type !== MESSAGE_TYPE) {
    throw new ConnectorError("invalid_pairing_request");
  }
  const apiOrigin = validateConfiguredOrigin(message, sender);
  if (typeof message.pairingId !== "string" || !SAFE_PAIRING_ID.test(message.pairingId)) {
    throw new ConnectorError("invalid_pairing_id");
  }
  if (typeof message.token !== "string" || !SAFE_PAIRING_TOKEN.test(message.token)) {
    throw new ConnectorError("invalid_pairing_token");
  }

  return Object.freeze({
    apiOrigin,
    pairingId: message.pairingId,
    token: message.token
  });
}

function permissionPattern(origin) {
  const url = new URL(origin);
  return `${url.protocol}//${url.hostname}/*`;
}

function runtimePermissions(origin) {
  return {
    permissions: ["cookies"],
    origins: [LINKEDIN_PERMISSION_PATTERN, permissionPattern(origin)]
  };
}

function linkedinReadPermissions() {
  return {
    permissions: ["cookies"],
    origins: [LINKEDIN_PERMISSION_PATTERN]
  };
}

function apiOriginPermissions(origin) {
  return {origins: [permissionPattern(origin)]};
}

async function ensureRuntimePermissions(requested) {
  let granted = false;
  try {
    granted = await chrome.permissions.request(requested);
  } catch {
    throw new ConnectorError("permission_request_failed");
  }
  if (!granted) {
    throw new ConnectorError("permission_denied");
  }
}

async function releaseRuntimePermissions(requested) {
  try {
    const removed = await chrome.permissions.remove(requested);
    if (!removed) {
      throw new Error("not_removed");
    }
  } catch {
    throw new ConnectorError("permission_release_failed");
  }
}

async function revokeResidualPermissionsAtStartup() {
  const origins = globalThis.LINKEDIN_CONNECTOR_CONFIG?.allowedApiOrigins;
  if (!Array.isArray(origins)) {
    return false;
  }
  try {
    // A previous worker may have been terminated between permission grant and
    // cleanup. Remove every possible residual scope before accepting a new
    // external message; false simply means that scope was not present.
    await chrome.permissions.remove(linkedinReadPermissions());
    for (const origin of origins) {
      await chrome.permissions.remove(apiOriginPermissions(origin));
    }
    return true;
  } catch {
    return false;
  }
}

let startupPermissionCleanupState = "pending";
const startupPermissionCleanup = revokeResidualPermissionsAtStartup().then((ready) => {
  startupPermissionCleanupState = ready ? "ready" : "failed";
  return ready;
});

async function handleReady(message, sender) {
  if (!message || message.type !== READY_MESSAGE_TYPE) {
    throw new ConnectorError("invalid_ready_request");
  }
  validateConfiguredOrigin(message, sender);
  const ready = await startupPermissionCleanup;
  if (!ready) {
    throw new ConnectorError("permission_cleanup_failed");
  }
  return {ok: true, ready: true};
}

function cookieIdentity(cookie) {
  return `${cookie.name}\u0000${cookie.domain}\u0000${cookie.path}`;
}

function serializeCookie(cookie) {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: cookie.sameSite,
    hostOnly: Boolean(cookie.hostOnly),
    session: Boolean(cookie.session),
    expirationDate:
      typeof cookie.expirationDate === "number" ? cookie.expirationDate : null
  };
}

async function collectLinkedInCookies() {
  const cookieLists = await Promise.all(
    LINKEDIN_COOKIE_URLS.map((url) => chrome.cookies.getAll({url}))
  );
  const uniqueCookies = new Map();
  for (const cookie of cookieLists.flat()) {
    uniqueCookies.set(cookieIdentity(cookie), serializeCookie(cookie));
  }

  const cookies = [...uniqueCookies.values()];
  const names = new Set(cookies.map((cookie) => cookie.name));
  if (!REQUIRED_COOKIE_NAMES.every((name) => names.has(name))) {
    throw new ConnectorError("linkedin_session_missing");
  }
  return cookies;
}

async function completePairing(request, cookies) {
  const pairingId = encodeURIComponent(request.pairingId);
  const endpoint = `${request.apiOrigin}/api/pairings/${pairingId}/complete`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${request.token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({cookies}),
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer"
  });

  if (!response.ok) {
    throw new ConnectorError(`pairing_rejected_${response.status}`);
  }
  return response.status;
}

async function handlePairing(message, sender) {
  if (transferInFlight) {
    throw new ConnectorError("transfer_in_progress");
  }
  transferInFlight = true;
  try {
    if (startupPermissionCleanupState === "pending") {
      throw new ConnectorError("connector_initializing");
    }
    if (startupPermissionCleanupState !== "ready") {
      throw new ConnectorError("permission_cleanup_failed");
    }
    const request = validatePairRequest(message, sender);
    const requested = runtimePermissions(request.apiOrigin);
    const linkedinAccess = linkedinReadPermissions();
    const apiAccess = apiOriginPermissions(request.apiOrigin);
    await ensureRuntimePermissions(requested);
    let linkedinAccessReleased = false;
    try {
      const cookies = await collectLinkedInCookies();
      // Remove cookie + LinkedIn access before the server starts its live
      // probes. A cleanup failure aborts before any credential upload.
      await releaseRuntimePermissions(linkedinAccess);
      linkedinAccessReleased = true;
      const status = await completePairing(request, cookies);
      return {ok: true, status, cookieCount: cookies.length};
    } finally {
      let releaseError = null;
      if (!linkedinAccessReleased) {
        try {
          await releaseRuntimePermissions(linkedinAccess);
        } catch (error) {
          releaseError = error;
        }
      }
      try {
        await releaseRuntimePermissions(apiAccess);
      } catch (error) {
        releaseError = releaseError || error;
      }
      if (releaseError) {
        throw releaseError;
      }
    }
  } finally {
    transferInFlight = false;
  }
}

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (!message || ![MESSAGE_TYPE, READY_MESSAGE_TYPE].includes(message.type)) {
    return false;
  }

  const operation = message.type === READY_MESSAGE_TYPE
    ? handleReady(message, sender)
    : handlePairing(message, sender);
  operation
    .then((result) => sendResponse(result))
    .catch((error) => {
      const code = error instanceof ConnectorError ? error.code : "pairing_failed";
      sendResponse({ok: false, error: code});
    });
  return true;
});
