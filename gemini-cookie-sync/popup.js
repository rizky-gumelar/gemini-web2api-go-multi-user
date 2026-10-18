const $ = (id) => document.getElementById(id);

async function load() {
  const cfg = await chrome.runtime.sendMessage({ type: 'getCfg' });
  $('baseUrl').value = cfg.baseUrl || '';
  $('apiKey').value = cfg.apiKey || '';
  $('label').value = cfg.label || '';
  await refreshStatus();
}

async function refreshStatus() {
  const el = $('status'), tags = $('tags');
  const st = await chrome.runtime.sendMessage({ type: 'status' }).catch(() => null);
  if (!st) { el.className = 'status bad'; el.textContent = 'Extension error.'; return; }
  if (st.loggedIn) {
    el.className = 'status ok';
    el.textContent = `Logged in to Gemini — ${st.count} cookies available.`;
  } else {
    el.className = 'status bad';
    el.textContent = 'Not logged in to Gemini. Open gemini.google.com and sign in.';
  }
  tags.innerHTML = st.present.map(k => `<span class="tag">${k}</span>`).join('')
    + st.missing.map(k => `<span class="tag miss">${k}</span>`).join('');
}

$('saveBtn').onclick = async () => {
  await chrome.runtime.sendMessage({
    type: 'saveCfg',
    cfg: {
      baseUrl: $('baseUrl').value.trim(),
      apiKey: $('apiKey').value.trim(),
      label: $('label').value.trim(),
    },
  });
  $('status').className = 'status';
  $('status').textContent = 'Settings saved.';
};

$('pushBtn').onclick = async () => {
  const btn = $('pushBtn');
  btn.disabled = true; btn.textContent = 'Sending…';
  const r = await chrome.runtime.sendMessage({
    type: 'push',
    cfg: {
      baseUrl: $('baseUrl').value.trim(),
      apiKey: $('apiKey').value.trim(),
      label: $('label').value.trim(),
    },
  }).catch(e => ({ ok: false, error: String(e) }));
  btn.disabled = false; btn.textContent = 'Send cookies now';
  const el = $('status');
  if (r && r.ok) {
    el.className = 'status ok';
    el.textContent = `Imported as account #${r.id} (${r.cookies} cookies).`;
  } else {
    el.className = 'status bad';
    el.textContent = (r && r.error) || 'Failed.';
  }
};

load();
