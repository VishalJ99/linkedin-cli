(() => {
  "use strict";

  const dashboard = document.querySelector("[data-dashboard]");
  if (!dashboard) return;

  const csrfToken = dashboard.dataset.csrfToken;
  const extensionId = dashboard.dataset.extensionId;
  const gateState = dashboard.dataset.gateState;
  const connected = dashboard.dataset.connected === "true";
  const statusNode = dashboard.querySelector("[data-action-status]");
  const connectButton = dashboard.querySelector("[data-connect]");
  const probeButton = dashboard.querySelector("[data-probe]");
  const disconnectButton = dashboard.querySelector("[data-disconnect]");
  const deleteButton = dashboard.querySelector("[data-delete]");
  let preparedPairing = null;
  let pairingPreparation = null;

  const setStatus = (message) => {
    statusNode.textContent = message;
  };

  const apiRequest = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    if (options.method && options.method !== "GET") {
      headers.set("X-CSRF-Token", csrfToken);
    }
    const response = await fetch(path, { ...options, headers });
    const payload = await response.json().catch(() => ({ detail: "Request failed." }));
    if (!response.ok) {
      throw new Error(typeof payload.detail === "string" ? payload.detail : "Request failed.");
    }
    return payload;
  };

  const sendExtensionMessage = (message) => new Promise((resolve, reject) => {
    if (!window.chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
      reject(new Error("The private Chrome extension is not available in this browser."));
      return;
    }
    chrome.runtime.sendMessage(extensionId, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error("The private Chrome extension could not be reached."));
        return;
      }
      if (!response || response.ok !== true) {
        reject(new Error(response && response.error ? response.error : "LinkedIn connection failed."));
        return;
      }
      resolve(response);
    });
  });

  const preparePairing = () => {
    if (["passed", "rejected", "retry_exhausted"].includes(gateState) || connected || pairingPreparation) return;
    connectButton.disabled = true;
    connectButton.textContent = "Preparing connector…";
    pairingPreparation = apiRequest("/api/pairings", { method: "POST" })
      .then(async (pairing) => {
        await sendExtensionMessage({
          type: "CONNECTOR_READY",
          apiBase: pairing.api_base,
        });
        preparedPairing = pairing;
        connectButton.disabled = false;
        connectButton.textContent = "Connect LinkedIn";
      })
      .catch((error) => {
        setStatus(error.message || "Could not prepare the connector.");
        connectButton.textContent = "Preparation failed";
      })
      .finally(() => {
        pairingPreparation = null;
      });
  };

  connectButton.addEventListener("click", () => {
    const pairing = preparedPairing;
    if (!pairing || Date.parse(pairing.expires_at) <= Date.now() + 5000) {
      preparedPairing = null;
      setStatus("Preparing a fresh one-time pairing. Choose Connect again when ready.");
      preparePairing();
      return;
    }
    preparedPairing = null;
    connectButton.disabled = true;
    setStatus("Waiting for the private Chrome extension…");
    // The extension message is sent synchronously inside this click handler so
    // Chrome can enforce permissions.request() against a real user activation.
    sendExtensionMessage({
        type: "PAIR_LINKEDIN",
        pairingId: pairing.pairing_id,
        token: pairing.pairing_token,
        apiBase: pairing.api_base,
      })
      .then(async () => {
        setStatus("LinkedIn connection encrypted. Running the first read probe…");
        const result = await apiRequest("/api/linkedin/probe", { method: "POST" });
        setStatus(result.status === "passed" ? "First probe passed." : "First probe recorded.");
        window.location.reload();
      })
      .catch((error) => {
        setStatus(error.message || "LinkedIn connection failed.");
        window.setTimeout(() => window.location.reload(), 1500);
      });
  });

  probeButton.addEventListener("click", async () => {
    probeButton.disabled = true;
    setStatus("Running the authenticated read probe…");
    try {
      const result = await apiRequest("/api/linkedin/probe", { method: "POST" });
      setStatus(result.status === "passed" ? "Probe passed." : "Probe did not pass; review is required.");
      window.location.reload();
    } catch (error) {
      setStatus(error.message || "Probe failed.");
      probeButton.disabled = false;
    }
  });

  disconnectButton.addEventListener("click", async () => {
    disconnectButton.disabled = true;
    setStatus("Deleting the encrypted LinkedIn session…");
    try {
      await apiRequest("/api/linkedin/disconnect", { method: "POST" });
      window.location.reload();
    } catch (error) {
      setStatus(error.message || "Disconnect failed.");
      disconnectButton.disabled = false;
    }
  });

  deleteButton.addEventListener("click", async () => {
    const confirmed = window.confirm(
      "Delete the encrypted LinkedIn session and all pairing and probe records? This cannot be undone."
    );
    if (!confirmed) return;
    deleteButton.disabled = true;
    setStatus("Deleting all private data…");
    try {
      await apiRequest("/api/data", { method: "DELETE" });
      window.location.assign("/login");
    } catch (error) {
      setStatus(error.message || "Data deletion failed.");
      deleteButton.disabled = false;
    }
  });

  preparePairing();
})();
