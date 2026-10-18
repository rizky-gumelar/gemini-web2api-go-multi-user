// Gemini Cookie Sync — background service worker
// Reads gemini.google.com cookies via chrome.cookies (works on httpOnly) and POSTs them
// to the configured gemini-web2api instance using the user's API key.

const GEMINI_DOMAINS = ['https://gemini.google.com', 'https://accounts.google.com', 'https://www.google.com'];
const KEY_COOKIES = ['SAPISID', '__Secure-1PSID', 'SID', 'HSID', 'SSID', 'APISID', '__Secure-1PSIDTS'];

const DEFAULT_CFG = { baseUrl: 'https://gemini.spacey.my.id', apiKey: '', label: '' };

async function getCfg() {
  const s = await chrome.storage.local.get(DEFAULT_CFG);
  return { ...DEFAULT_CFG, ...s };
}

async function saveCfg(cfg) {
  await chrome.storage.local.set(cfg);
}

// Collect all cookies that belong to the Gemini web session.
async function collectCookies() {
  const byName = new Map();
  for (const url of GEMINI_DOMAINS) {
    let list = [];
    try {
      list = await chrome.cookies.getAll({ url });
    } catch (e) {
      continue;
    }
    for (const c of list) {
      // prefer the gemini.google.com scoped value when a name appears twice
      const prev = byName.get(c.name);
      if (!prev || (c.domain.includes('gemini') && !prev.domain.includes('gemini'))) {
        byName.set(c.name, c);
      }
    }
  }
  return byName;
}

function cookieStringFromMap(map) {
  return [...map.values()]
    .filter(c => c.value)
    .map(c => `${c.name}=${c.value}`)
    .join('; ');
}

async function status() {
  const map = await collectCookies();
  const present = KEY_COOKIES.filter(k => map.has(k) && map.get(k).value);
  return {
    loggedIn: present.includes('SAPISID') && present.includes('__Secure-1PSID'),
    present,
    missing: KEY_COOKIES.filter(k => !present.includes(k)),
    count: map.size,
  };
}

async function push(cfgOverride) {
  const cfg = { ...(await getCfg()), ...(cfgOverride || {}) };
  if (!cfg.baseUrl || !cfg.apiKey) {
    return { ok: false, error: 'Set the base URL and API key first.' };
  }
  const st = await status();
  if (!st.loggedIn) {
    return { ok: false, error: 'Not logged in to Gemini (missing SAPISID or __Secure-1PSID).' };
  }
  const map = await collectCookies();
  const cookie = cookieStringFromMap(map);
  const base = cfg.baseUrl.replace(/\/+$/, '');
  const label = (cfg.label || '').trim() || 'chrome-extension';

  let res, data;
  try {
    res = await fetch(`${base}/admin/api/cookies`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify({ label, cookie, note: 'imported by Gemini Cookie Sync extension' }),
    });
    data = await res.json().catch(() => ({}));
  } catch (e) {
    return { ok: false, error: `Network error: ${e.message}` };
  }

  if (!res.ok) {
    return { ok: false, error: data.error || `HTTP ${res.status}` };
  }
  return { ok: true, id: data.id, cookies: st.count };
}

// Message bridge for content script / popup.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'status':
          sendResponse(await status());
          break;
        case 'push':
          sendResponse(await push(msg.cfg));
          break;
        case 'getCfg':
          sendResponse(await getCfg());
          break;
        case 'saveCfg':
          await saveCfg(msg.cfg || {});
          sendResponse({ ok: true });
          break;
        case 'openGemini':
          await chrome.tabs.create({ url: 'https://gemini.google.com/app' });
          sendResponse({ ok: true });
          break;
        default:
          sendResponse({ ok: false, error: 'unknown message' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  })();
  return true; // async
});
