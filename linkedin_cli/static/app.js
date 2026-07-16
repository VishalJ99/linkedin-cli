(() => {
  "use strict";

  const dashboard = document.querySelector("[data-dashboard]");
  if (!dashboard) return;

  const csrfToken = dashboard.dataset.csrfToken;
  const gateState = dashboard.dataset.gateState;
  const connected = dashboard.dataset.connected === "true";
  const statusNode = dashboard.querySelector("[data-action-status]");
  const cookieInput = dashboard.querySelector("[data-cookie-header]");
  const connectButton = dashboard.querySelector("[data-connect-cookie]");
  const probeButton = dashboard.querySelector("[data-probe]");
  const disconnectButton = dashboard.querySelector("[data-disconnect]");
  const deleteButton = dashboard.querySelector("[data-delete]");

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

  connectButton.addEventListener("click", async () => {
    const cookieHeader = cookieInput.value.trim();
    if (!cookieHeader) {
      setStatus("Paste the LinkedIn Cookie header first.");
      cookieInput.focus();
      return;
    }
    connectButton.disabled = true;
    cookieInput.disabled = true;
    cookieInput.value = "";
    setStatus("Validating and encrypting the LinkedIn session…");
    let sessionStored = false;
    try {
      await apiRequest("/api/linkedin/connect-cookie", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cookie_header: cookieHeader }),
      });
      sessionStored = true;
      setStatus("Session encrypted. Running the first read probe once…");
      const result = await apiRequest("/api/linkedin/probe", { method: "POST" });
      setStatus(result.status === "passed" ? "First probe passed." : "First probe recorded.");
      window.location.reload();
    } catch (error) {
      if (sessionStored) {
        setStatus(
          `${error.message || "The first probe could not run."} The session is encrypted; use Run probe now only if the gate remains open.`
        );
        probeButton.disabled = ["passed", "rejected", "retry_exhausted"].includes(gateState);
      } else {
        setStatus(error.message || "Could not connect the LinkedIn session.");
        connectButton.disabled = connected || ["passed", "rejected", "retry_exhausted"].includes(gateState);
        cookieInput.disabled = connectButton.disabled;
      }
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
      "Delete the encrypted LinkedIn session and all probe records? This cannot be undone."
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
