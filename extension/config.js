/*
 * This production allow-list is intentionally empty until Railway assigns the
 * gate domain. Before side-loading, replace the empty list with only the exact
 * PUBLIC_BASE_URL origin, then commit and deploy that same revision. Never add
 * localhost to the production connector.
 * The broad Railway match in manifest.json only lets a page ask to connect;
 * this exact allow-list is what permits the service worker to read cookies.
 */
globalThis.LINKEDIN_CONNECTOR_CONFIG = Object.freeze({
  allowedApiOrigins: Object.freeze([])
});
