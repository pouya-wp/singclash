import yaml from 'js-yaml';
import { convertSingbox } from './singbox-to-clash.js';
import { parseManual, parseUri, proxiesFromStructured } from './manual-parser.js';

const FETCH_TIMEOUT_MS = 20000;

/** Fetches the upstream subscription with the configured User-Agent. */
export async function fetchSubscription(url, userAgent) {
  const res = await fetch(url, {
    headers: { 'User-Agent': userAgent, Accept: 'application/json, */*' },
    redirect: 'follow',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`سرور سابسکریپشن پاسخ ${res.status} ${res.statusText} داد`);
  const body = await res.text();
  return {
    body,
    userinfo: res.headers.get('subscription-userinfo'),
    updateInterval: res.headers.get('profile-update-interval'),
  };
}

function tryBase64(text) {
  const s = text.replace(/\s+/g, '');
  if (!s || !/^[A-Za-z0-9+/=_-]+$/.test(s)) return null;
  try {
    const decoded = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return /:\/\//.test(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

/**
 * Turns the upstream body into Clash proxies. sing-box JSON is the expected format, but a
 * Clash YAML or a (base64) list of share links is accepted too so a misconfigured
 * User-Agent doesn't break the profile.
 */
export function parseSubscriptionBody(body) {
  const text = body.replace(/^﻿/, '').trim();
  if (text.startsWith('{') || text.startsWith('[')) {
    const json = JSON.parse(text);
    return { format: 'sing-box', ...convertSingbox(json) };
  }
  try {
    const doc = yaml.load(text);
    if (doc && typeof doc === 'object' && Array.isArray(doc.proxies)) {
      return { format: 'clash', ...proxiesFromStructured(doc) };
    }
  } catch {
    /* not YAML */
  }
  const links = tryBase64(text) ?? text;
  const proxies = [];
  const skipped = [];
  for (const line of links.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) {
    try {
      proxies.push(parseUri(line));
    } catch {
      skipped.push(line.slice(0, 40));
    }
  }
  if (!proxies.length) throw new Error('محتوای سابسکریپشن قابل تشخیص نبود (نه JSON ساین‌باکس، نه YAML کلش، نه لیست لینک)');
  return { format: 'links', proxies, skipped };
}

function uniqueNames(proxies) {
  const used = new Set();
  for (const p of proxies) {
    const base = String(p.name || `${p.type}-${p.server}`).trim();
    let name = base;
    for (let i = 2; used.has(name); i++) name = `${base} ${i}`;
    used.add(name);
    p.name = name;
  }
  return proxies;
}

// Mihomo-specific fixes for proxies that come from manual input or other clients' formats.
function normalize(proxies, warnings) {
  for (const p of proxies) {
    // Mihomo only implements Snell v1-v3; v4/v5 servers stay compatible with v3 clients.
    if (p.type === 'snell' && Number(p.version) > 3) {
      warnings.push(`«${p.name}»: Snell v${p.version} در Mihomo پشتیبانی نمی‌شود؛ با v3 (سازگار با سرور v4/v5) متصل می‌شود`);
      p.version = 3;
    }
  }
  return proxies;
}

/** Builds the full Mihomo profile object from already-collected proxies. */
export function buildProfile(cfg, proxies) {
  const names = proxies.map((p) => p.name);
  const auto = cfg.autoGroup;
  const rules = [
    'DOMAIN-SUFFIX,local,DIRECT',
    'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
  ];
  if (cfg.bypassIran) rules.push('DOMAIN-SUFFIX,ir,DIRECT', 'GEOIP,IR,DIRECT');
  rules.push(`MATCH,${cfg.mainGroupName}`);

  return {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    ipv6: false,
    'unified-delay': true,
    'tcp-concurrent': true,
    'external-controller': '127.0.0.1:9090',
    dns: {
      enable: true,
      ipv6: false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'fake-ip-filter': ['*.lan', '+.local', '+.msftconnecttest.com', '+.msftncsi.com'],
      'default-nameserver': ['1.1.1.1', '8.8.8.8'],
      nameserver: ['https://1.1.1.1/dns-query', 'https://dns.google/dns-query'],
      'proxy-server-nameserver': ['1.1.1.1', '8.8.8.8'],
    },
    proxies,
    'proxy-groups': [
      {
        name: cfg.mainGroupName,
        type: 'select',
        proxies: [auto.name, ...names, 'DIRECT'],
      },
      {
        name: auto.name,
        type: 'url-test',
        // url-test with an empty list is a config error in Mihomo, so fall back to DIRECT.
        proxies: names.length ? names : ['DIRECT'],
        url: auto.url,
        interval: auto.interval,
        tolerance: auto.tolerance,
        lazy: false,
      },
    ],
    rules,
  };
}

/**
 * Fetches + converts the subscription, merges the manual configs and returns the YAML text
 * along with stats for the panel. Throws only if there is nothing at all to serve.
 */
export async function generate(cfg) {
  const stats = { format: null, subscription: 0, manual: 0, skipped: [], errors: [], userinfo: null };
  let subProxies = [];
  if (cfg.subscriptionUrl) {
    try {
      const fetched = await fetchSubscription(cfg.subscriptionUrl, cfg.userAgent);
      const parsed = parseSubscriptionBody(fetched.body);
      subProxies = parsed.proxies;
      stats.format = parsed.format;
      stats.skipped.push(...parsed.skipped);
      stats.userinfo = fetched.userinfo;
    } catch (e) {
      const reason = e.name === 'TimeoutError' ? 'مهلت اتصال به سرور سابسکریپشن تمام شد' : e.message;
      stats.errors.push(`سابسکریپشن: ${reason}`);
      stats.subscriptionFailed = true;
    }
  }
  const manual = parseManual(cfg.manualConfigs);
  stats.errors.push(...manual.errors.map((m) => `کانفیگ دستی — ${m}`));

  const proxies = uniqueNames(normalize([...subProxies, ...manual.proxies], stats.errors));
  stats.subscription = subProxies.length;
  stats.manual = manual.proxies.length;
  stats.total = proxies.length;

  const profile = buildProfile(cfg, proxies);
  const text = yaml.dump(profile, { lineWidth: -1, noRefs: true, quotingType: '"' });
  return { yaml: text, stats };
}
