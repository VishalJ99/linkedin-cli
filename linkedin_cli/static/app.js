(() => {
  "use strict";

  const dashboard = document.querySelector("[data-dashboard]");
  if (!dashboard) return;

  const csrfToken = dashboard.dataset.csrfToken;
  const gateState = dashboard.dataset.gateState;
  const connected = dashboard.dataset.connected === "true";
  const statusNode = dashboard.querySelector("[data-action-status]");
  const downloadButton = dashboard.querySelector("[data-download-connector]");
  const probeButton = dashboard.querySelector("[data-probe]");
  const disconnectButton = dashboard.querySelector("[data-disconnect]");
  const deleteButton = dashboard.querySelector("[data-delete]");
  let automaticProbeStarted = false;

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

  const wait = (milliseconds) => new Promise((resolve) => {
    window.setTimeout(resolve, milliseconds);
  });

  const pollDownloadedPairing = async (pairingId) => {
    const deadline = Date.now() + (10 * 60 * 1000);
    while (Date.now() < deadline) {
      const pairing = await apiRequest(`/api/pairings/${encodeURIComponent(pairingId)}`);
      if (pairing.state === "expired") {
        setStatus("The connector expired. Download a fresh connector when you are ready.");
        downloadButton.disabled = false;
        return;
      }
      if (pairing.state === "completed") {
        if (automaticProbeStarted) return;
        automaticProbeStarted = true;
        setStatus("LinkedIn connection encrypted. Running the first read probe once…");
        try {
          const result = await apiRequest("/api/linkedin/probe", { method: "POST" });
          setStatus(result.status === "passed" ? "First probe passed." : "First probe recorded.");
          window.location.reload();
        } catch (error) {
          setStatus(
            `${error.message || "The first probe could not run."} The session is connected; use Run probe now to retry manually.`
          );
          probeButton.disabled = false;
        }
        return;
      }
      await wait(2000);
    }
    setStatus("The connector expired. Download a fresh connector when you are ready.");
    downloadButton.disabled = false;
  };

  downloadButton.addEventListener("click", async () => {
    downloadButton.disabled = true;
    setStatus("Preparing a ten-minute, single-use Mac connector…");
    try {
      const response = await fetch("/api/connectors/macos", {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({ detail: "Download failed." }));
        throw new Error(typeof payload.detail === "string" ? payload.detail : "Download failed.");
      }
      const pairingId = response.headers.get("X-Pairing-ID");
      if (!pairingId) throw new Error("The connector download was incomplete.");
      const connector = await response.blob();
      const downloadUrl = URL.createObjectURL(connector);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = "LinkedIn-Connector.zip";
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
      setStatus(
        "Downloaded. Extract the ZIP, open Connect LinkedIn.command, and sign into the temporary Chrome profile."
      );
      await pollDownloadedPairing(pairingId);
    } catch (error) {
      setStatus(error.message || "Could not download the Mac connector.");
      downloadButton.disabled = false;
    }
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
})();
