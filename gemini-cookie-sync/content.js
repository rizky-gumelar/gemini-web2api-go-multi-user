// Content script — runs on the gemini-web2api admin panel.
// Detects that the page is the panel, checks login state, and offers a confirm popup.

(async () => {
  const isPanel = /\/admin\/?$/.test(location.pathname) || location.pathname === '/admin';
  if (!isPanel) return;

  const cfg = await chrome.runtime.sendMessage({ type: 'getCfg' }).catch(() => null);
  // only auto-prompt on instances the user configured
  const host = location.origin.replace(/\/+$/, '');
  if (!cfg || (cfg.baseUrl || '').replace(/\/+$/, '') !== host) return;

  const st = await chrome.runtime.sendMessage({ type: 'status' }).catch(() => null);
  if (!st || !st.loggedIn) return; // not logged in to Gemini — stay silent

  const seenKey = 'gcs_prompt_' + location.host;
  const seen = await chrome.storage?.local?.get?.(seenKey).catch?.(() => null);
  if (seen && seen[seenKey]) return; // already asked in this browser for this host

  showBanner(st);
})();

function showBanner(st) {
  const box = document.createElement('div');
  box.id = 'gemini-cookie-sync-banner';
  box.style.cssText = [
    'position:fixed', 'right:20px', 'bottom:20px', 'z-index:2147483647',
    'width:340px', 'padding:16px 18px', 'border-radius:14px',
    'background:#1f1f1f', 'color:#fff', 'font:13px/1.5 system-ui,sans-serif',
    'box-shadow:0 8px 28px rgba(0,0,0,.35)',
  ].join(';');

  box.innerHTML = `
    <div style="font-weight:600;margin-bottom:6px">Gemini account detected</div>
    <div style="opacity:.85;margin-bottom:12px">
      Found ${st.present.length} key cookies for gemini.google.com.
      Send them to this panel so Pro / thinking / image models unlock?
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button id="gcs-no" style="background:transparent;border:1px solid #555;color:#ccc;
        padding:7px 14px;border-radius:8px;cursor:pointer;font-size:13px">Not now</button>
      <button id="gcs-yes" style="background:#0b57d0;border:0;color:#fff;
        padding:7px 14px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600">Send cookies</button>
    </div>
    <div id="gcs-msg" style="margin-top:10px;font-size:12px;opacity:.8"></div>
  `;
  document.body.appendChild(box);

  const msg = box.querySelector('#gcs-msg');
  const remember = async () => {
    try { await chrome.storage.local.set({ ['gcs_prompt_' + location.host]: true }); } catch (e) {}
  };

  box.querySelector('#gcs-no').onclick = async () => { await remember(); box.remove(); };
  box.querySelector('#gcs-yes').onclick = async (e) => {
    const btn = e.target;
    btn.disabled = true; btn.textContent = 'Sending…';
    msg.textContent = '';
    const r = await chrome.runtime.sendMessage({ type: 'push' }).catch(err => ({ ok: false, error: String(err) }));
    if (r && r.ok) {
      msg.style.color = '#7fe08a';
      msg.textContent = `Imported as account #${r.id} (${r.cookies} cookies). Reload to see it.`;
      btn.textContent = 'Done';
      await remember();
      setTimeout(() => location.reload(), 1200);
    } else {
      msg.style.color = '#ff8a80';
      msg.textContent = (r && r.error) || 'Failed.';
      btn.disabled = false; btn.textContent = 'Send cookies';
    }
  };
}
