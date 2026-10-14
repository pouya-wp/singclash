// Settings storage. Locally the settings live in config.json; on serverless hosts such as
// Vercel (read-only, ephemeral filesystem) they live in Upstash Redis via its REST API.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const CONFIG_PATH = path.resolve(process.env.CONFIG_PATH || 'config.json');
const REDIS_URL = (process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, '');
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REDIS_KEY = process.env.CONFIG_KEY || 'singclash:config';
export const IS_SERVERLESS = Boolean(process.env.VERCEL);

export function newToken() {
  return crypto.randomBytes(18).toString('base64url');
}

export function defaults() {
  return {
    subscriptionUrl: '',
    userAgent: 'sing-box',
    token: newToken(),
    profileName: 'SingClash',
    updateInterval: 12,
    manualConfigs: '',
    mainGroupName: 'PROXY',
    autoGroup: {
      name: 'Auto',
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      tolerance: 50,
    },
    bypassIran: true,
  };
}

const fileBackend = {
  name: 'file',
  async read() {
    if (!fs.existsSync(CONFIG_PATH)) return null;
    try {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (e) {
      console.error(`[config] could not parse ${CONFIG_PATH}: ${e.message} — using defaults`);
      return null;
    }
  },
  async write(cfg) {
    const tmp = `${CONFIG_PATH}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n');
    fs.renameSync(tmp, CONFIG_PATH);
  },
};

async function redis(command) {
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
    signal: AbortSignal.timeout(8000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error) throw new Error(`Redis: ${data.error || `HTTP ${res.status}`}`);
  return data.result;
}

const redisBackend = {
  name: 'redis',
  async read() {
    const raw = await redis(['GET', REDIS_KEY]);
    return raw ? JSON.parse(raw) : null;
  },
  async write(cfg) {
    await redis(['SET', REDIS_KEY, JSON.stringify(cfg)]);
  },
};

const backend = REDIS_URL && REDIS_TOKEN ? redisBackend : fileBackend;
export const STORAGE = backend.name === 'redis' ? 'Upstash Redis' : CONFIG_PATH;

/** True when settings can't be persisted (serverless host without Redis configured). */
export function storageMissing() {
  return IS_SERVERLESS && backend === fileBackend;
}

// The file backend keeps a process-wide cache; Redis is re-read on every request because
// serverless instances don't share memory.
let cached = null;

export async function getConfig() {
  if (cached && backend === fileBackend) return cached;
  const base = defaults();
  const stored = (await backend.read()) || {};
  const cfg = { ...base, ...stored, autoGroup: { ...base.autoGroup, ...(stored.autoGroup || {}) } };
  // First run: persist the generated token so the output link stays stable.
  if (!stored.token && !storageMissing()) await backend.write(cfg);
  cached = cfg;
  return cfg;
}

export async function saveConfig(cfg) {
  if (storageMissing()) {
    throw new Error('روی Vercel باید Upstash Redis را وصل کنید تا تنظیمات ذخیره شوند (راهنما در README)');
  }
  await backend.write(cfg);
  cached = cfg;
  return cfg;
}

const clampInt = (v, min, max, fallback) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
};

/** Merges a (partial) settings payload from the panel into a full, validated config. */
export function sanitize(input, prev) {
  const d = defaults();
  const str = (v, fallback) => (typeof v === 'string' ? v.trim() : fallback);
  const ag = input.autoGroup || {};
  const out = {
    ...prev,
    subscriptionUrl: str(input.subscriptionUrl, prev.subscriptionUrl),
    userAgent: str(input.userAgent, prev.userAgent) || d.userAgent,
    profileName: str(input.profileName, prev.profileName) || d.profileName,
    updateInterval: clampInt(input.updateInterval ?? prev.updateInterval, 1, 168, d.updateInterval),
    manualConfigs: typeof input.manualConfigs === 'string' ? input.manualConfigs : prev.manualConfigs,
    mainGroupName: str(input.mainGroupName, prev.mainGroupName) || d.mainGroupName,
    autoGroup: {
      name: str(ag.name, prev.autoGroup.name) || d.autoGroup.name,
      url: str(ag.url, prev.autoGroup.url) || d.autoGroup.url,
      interval: clampInt(ag.interval ?? prev.autoGroup.interval, 10, 86400, d.autoGroup.interval),
      tolerance: clampInt(ag.tolerance ?? prev.autoGroup.tolerance, 0, 5000, d.autoGroup.tolerance),
    },
    bypassIran: typeof input.bypassIran === 'boolean' ? input.bypassIran : prev.bypassIran,
  };
  if (out.subscriptionUrl && !/^https?:\/\//i.test(out.subscriptionUrl)) {
    throw new Error('لینک سابسکریپشن باید با http:// یا https:// شروع شود');
  }
  if (out.mainGroupName === out.autoGroup.name) {
    throw new Error('نام گروه اصلی و گروه url-test نباید یکسان باشند');
  }
  return out;
}
