const $ = (id) => document.getElementById(id);
let config = null;
let publicUrl = null;
let storage = null;
let dirty = false;

const fa = (n) => Number(n || 0).toLocaleString('fa-IR');

function toast(msg, kind = 'ok') {
  const el = $('toast');
  el.textContent = msg;
  el.classList.toggle('border-rose-400/40', kind === 'err');
  el.classList.remove('opacity-0', 'translate-y-[-150%]');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => el.classList.add('opacity-0', 'translate-y-[-150%]'), 2600);
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function subLink() {
  const origin = publicUrl || location.origin;
  return `${origin}/sub?token=${encodeURIComponent(config.token)}`;
}

function fill() {
  $('subscriptionUrl').value = config.subscriptionUrl;
  $('userAgent').value = config.userAgent;
  $('profileName').value = config.profileName;
  $('updateInterval').value = config.updateInterval;
  $('manualConfigs').value = config.manualConfigs;
  $('mainGroupName').value = config.mainGroupName;
  $('autoName').value = config.autoGroup.name;
  $('autoUrl').value = config.autoGroup.url;
  $('autoInterval').value = config.autoGroup.interval;
  $('autoTolerance').value = config.autoGroup.tolerance;
  $('bypassIran').checked = config.bypassIran;
  $('subLink').value = subLink();
  setDirty(false);
}

function collect() {
  return {
    subscriptionUrl: $('subscriptionUrl').value,
    userAgent: $('userAgent').value,
    profileName: $('profileName').value,
    updateInterval: $('updateInterval').value,
    manualConfigs: $('manualConfigs').value,
    mainGroupName: $('mainGroupName').value,
    autoGroup: {
      name: $('autoName').value,
      url: $('autoUrl').value,
      interval: $('autoInterval').value,
      tolerance: $('autoTolerance').value,
    },
    bypassIran: $('bypassIran').checked,
  };
}

function setDirty(v) {
  dirty = v;
  const s = $('status');
  s.textContent = v ? 'تغییرات ذخیره نشده' : 'ذخیره‌شده';
  s.className = v
    ? 'hidden rounded-full border border-amber-400/20 bg-amber-400/10 px-3 py-1 text-xs text-amber-300 sm:inline'
    : 'hidden rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs text-emerald-300 sm:inline';
}

async function copy(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for non-HTTPS origins where the async clipboard API is unavailable.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(okMsg);
}

function withBusy(btn, fn) {
  return async () => {
    btn.disabled = true;
    try {
      await fn();
    } catch (e) {
      toast(e.message, 'err');
    } finally {
      btn.disabled = false;
    }
  };
}

function renderPreview({ yaml, stats }) {
  $('previewCard').classList.remove('hidden');
  $('yaml').textContent = yaml;
  const formats = { 'sing-box': 'JSON ساین‌باکس', clash: 'YAML کلش', links: 'لیست لینک' };
  const items = [
    ['از سابسکریپشن', fa(stats.subscription)],
    ['دستی', fa(stats.manual)],
    ['مجموع', fa(stats.total)],
    ['فرمت دریافتی', formats[stats.format] || '—'],
  ];
  $('stats').innerHTML = items
    .map(([k, v]) => `<div class="stat"><div class="text-[11px] text-slate-500">${k}</div><div class="mt-0.5 font-bold text-white">${v}</div></div>`)
    .join('');
  const notes = [...stats.errors, ...stats.skipped.map((s) => `رد شد: ${s}`)];
  const ul = $('errors');
  ul.classList.toggle('hidden', !notes.length);
  ul.replaceChildren(...notes.map((n) => Object.assign(document.createElement('li'), { textContent: '• ' + n })));
  // Raw sample of a dropped outbound (secrets masked) — handy for reporting a new format.
  if (stats.samples?.length) {
    const li = document.createElement('li');
    li.className = 'pt-2';
    li.append('نمونه‌ی outbound ردشده (رمزها مخفی شده‌اند):');
    const pre = Object.assign(document.createElement('pre'), { textContent: JSON.stringify(stats.samples, null, 2) });
    pre.dir = 'ltr';
    pre.className = 'mt-1 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-black/30 p-2 font-mono text-[11px] text-slate-300';
    li.append(pre);
    ul.append(li);
  }
  $('previewCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function init() {
  try {
    ({ config, publicUrl, storage } = await api('GET', '/api/config'));
    if (!storage) toast('فضای ذخیره‌سازی تنظیم نشده؛ Upstash Redis را وصل کنید', 'err');
    fill();
  } catch (e) {
    toast('بارگذاری تنظیمات ناموفق بود: ' + e.message, 'err');
    return;
  }

  document.querySelectorAll('input, textarea').forEach((el) => {
    if (el.id !== 'subLink') el.addEventListener('input', () => setDirty(true));
  });
  $('bypassIran').addEventListener('change', () => setDirty(true));
  document.querySelectorAll('[data-ua]').forEach((chip) =>
    chip.addEventListener('click', () => {
      $('userAgent').value = chip.dataset.ua;
      setDirty(true);
    }),
  );

  $('copyLink').addEventListener('click', () => copy($('subLink').value, 'لینک کپی شد'));
  $('copyYaml').addEventListener('click', () => copy($('yaml').textContent, 'YAML کپی شد'));

  $('save').addEventListener(
    'click',
    withBusy($('save'), async () => {
      ({ config } = await api('PUT', '/api/config', collect()));
      fill();
      toast(storage === 'Upstash Redis' ? 'تنظیمات در Redis ذخیره شد' : 'تنظیمات در config.json ذخیره شد');
    }),
  );

  $('preview').addEventListener(
    'click',
    withBusy($('preview'), async () => {
      $('preview').lastChild.textContent = ' در حال دریافت…';
      try {
        renderPreview(await api('POST', '/api/preview', collect()));
      } finally {
        $('preview').lastChild.textContent = ' پیش‌نمایش';
      }
    }),
  );

  $('regen').addEventListener('click', async () => {
    if (!confirm('لینک فعلی باطل می‌شود و باید لینک جدید را در FlClash وارد کنید. ادامه می‌دهید؟')) return;
    try {
      const { config: updated } = await api('POST', '/api/token');
      // Only the token changes; unsaved edits in the form are left alone.
      config.token = updated.token;
      $('subLink').value = subLink();
      toast('توکن جدید ساخته شد');
    } catch (e) {
      toast(e.message, 'err');
    }
  });

  window.addEventListener('beforeunload', (e) => {
    if (dirty) e.preventDefault();
  });
}

init();
