# Private Chrome connector

This side-loaded Manifest V3 extension transfers the current Chrome profile's
LinkedIn cookie jar to one explicitly configured conversation-finder origin. It
does so only when that website sends a valid, single-use pairing request after
the user chooses **Connect LinkedIn**.

## Configure and load

The committed public manifest key gives this unpacked extension the stable ID
`ohjgceimoldkhlncabhahccapgoolknc`. Use that exact value for Railway's `EXTENSION_ID`.
The manifest key is public identity material, not a signing or session secret.

1. Replace the empty `allowedApiOrigins` list in `config.js` with only the exact
   `PUBLIC_BASE_URL` origin, commit that configuration, and deploy the same
   commit. Never add localhost to the production connector, and do not
   side-load an uncommitted edited copy.
2. If the site uses a custom domain rather than Railway's domain, add that exact
   match pattern to `optional_host_permissions` and `externally_connectable` in
   `manifest.json`.
3. Open `chrome://extensions`, enable **Developer mode**, choose **Load
   unpacked**, and select this `extension/` directory.
4. Chrome asks for LinkedIn-cookie and website access from the website's
   explicit **Connect LinkedIn** click. The extension calls
   `permissions.request()` for every transfer. It removes cookie and LinkedIn
   access immediately after the in-memory read and before uploading; it removes
   the site-origin permission after the short encrypted-storage response. On
   startup it clears any residual optional permission left by worker
   termination. Chrome, rather than a caller-provided flag, enforces user
   activation. If Chrome rejects that activation path, record the gate failure;
   do not add a background transfer fallback.
5. Sign in to LinkedIn in the same Chrome profile, then use **Connect LinkedIn**
   on the website. After encrypted storage returns, the website—not the
   extension—immediately starts the first two-read gate probe.

During page preparation the website sends a non-sensitive readiness message.
That wakes the service worker, completes residual-permission cleanup, and only
then enables Connect. The later permission request therefore remains the first
awaited operation inside the actual click handler.

The manifest's Railway patterns determine which pages can send a message. The
exact list in `config.js` is a second, stricter boundary checked before any
cookie read. Load `extension/` only from the clean commit recorded for the gate.
The extension does not use local extension storage, subscribe to cookie
changes, retain permissions after a transfer, retry failed transfers, or
perform any outreach action.
