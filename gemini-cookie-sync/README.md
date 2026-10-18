# Gemini Cookie Sync

Chrome extension (Manifest V3) that detects your **gemini.google.com** login and offers a
one-click confirm popup to send those session cookies to your self-hosted
**gemini-web2api** panel.

Without cookies the proxy only serves the two anonymous models. With them, the panel
unlocks `gemini-3.1-pro`, the `-thinking` variants, image / music / canvas generation
(paid Google accounts additionally unlock `gemini-3.8-flash` and `gemini-4-argon`).

## Why an extension

The panel *cannot* read these cookies from JavaScript. `__Secure-1PSID`, `SAPISID`, etc.
are **httpOnly** and scoped to `google.com`, so `document.cookie` on your panel origin
sees nothing. The `chrome.cookies` API is the only way a web page can obtain them, and
that requires an extension.

## Install (unpacked)

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select this folder (`gemini-cookie-sync`)
4. Pin the icon to the toolbar

## Configure

Click the extension icon and fill in:

- **Panel base URL** — e.g. `https://gemini.spacey.my.id`
- **Your API key** — the `sk-gemini-…` key for *your* account (panel → Settings page,
  or ask the admin). Each user has their own key; cookies land in that user's own pool.
- **Account label** — optional, e.g. `you@gmail.com`

Click **Save settings**.

## Use

**Automatic:** be logged in to `gemini.google.com` in the same Chrome profile, then open
`https://<your-panel>/admin/`. A banner appears in the bottom-right:

> Gemini account detected — Found 6 key cookies … Send them to this panel?

Click **Send cookies** → imported as a new cookie-pool account for your user.
Dismissing it with **Not now** remembers the choice per host.

**Manual:** click the toolbar icon → **Send cookies now**.

## What gets sent

Only cookies scoped to `gemini.google.com` / `accounts.google.com` / `www.google.com`,
serialized as `k=v; k=v; …` and POSTed to `/admin/api/cookies` with your Bearer key.
Nothing is sent to any third party — the extension talks only to the base URL you set.

Cookies are held in Chrome's own cookie jar; the extension stores just your settings
in `chrome.storage.local`.

## Notes

- Keep-alive (`__Secure-1PSIDTS` refresh) runs server-side every 10 minutes after import.
- If the panel marks the account red / "Likely expired", sign in to Gemini again in the
  browser and resend. Chrome's device-bound sessions (DBSC) may shorten cookie life;
  Firefox-exported cookies last longer, but the extension reads Chrome only.
- If `/v1/models` still lists just two models after importing, the cookie was rejected —
  open the panel's Cookie Pool page and hit **Check** on the account to see why.

## Files

| File | Purpose |
|---|---|
| `manifest.json` | MV3 manifest, permissions (`cookies`, `storage`) |
| `background.js` | Reads cookies, POSTs to the panel, message bridge |
| `content.js` | Detects the panel page, shows the confirm banner |
| `popup.html` / `popup.js` | Settings + "send now" UI |
| `icon128.png` | Toolbar icon |
