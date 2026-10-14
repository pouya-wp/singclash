import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getConfig, saveConfig, sanitize, newToken, storageMissing, IS_SERVERLESS, STORAGE } from './config-store.js';
import { generate } from './builder.js';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(express.json({ limit: '2mb' }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// ---------- Subscription endpoint (used by FlClash) ----------

async function serveSub(req, res) {
  const cfg = await getConfig();
  const token = req.params.token ?? req.query.token;
  if (storageMissing()) return res.status(503).type('text/plain').send('Storage is not configured');
  if (!token || !safeEqual(token, cfg.token)) return res.status(403).type('text/plain').send('Forbidden: invalid token');

  const { yaml, stats } = await generate(cfg);
  // If the upstream failed and there's nothing else, answer with an error so the client
  // keeps its previously downloaded profile instead of replacing it with an empty one.
  if (stats.subscriptionFailed && stats.total === 0) {
    return res.status(502).type('text/plain').send(stats.errors.join('\n'));
  }
  res.set({
    'Content-Type': 'text/yaml; charset=utf-8',
    'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(cfg.profileName || 'SingClash')}`,
    'Profile-Update-Interval': String(cfg.updateInterval),
    'Cache-Control': 'no-store',
  });
  if (stats.userinfo) res.set('Subscription-Userinfo', stats.userinfo);
  console.log(`[sub] served ${stats.total} proxies (sub=${stats.subscription}, manual=${stats.manual}) to ${req.get('user-agent') || '-'}`);
  if (stats.errors.length) console.warn('[sub] warnings:\n  ' + stats.errors.join('\n  '));
  res.send(yaml);
}

app.get('/sub', wrap(serveSub));
app.get('/sub/:token', wrap(serveSub));

// ---------- Panel API (optionally behind basic auth) ----------

function panelAuth(req, res, next) {
  if (!PANEL_PASSWORD) {
    // A public deployment without a password would expose the token and settings to anyone.
    if (IS_SERVERLESS) return res.status(503).json({ error: 'روی Vercel متغیر محیطی PANEL_PASSWORD را تنظیم کنید و دوباره Deploy کنید' });
    return next();
  }
  const [scheme, encoded] = (req.get('authorization') || '').split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString();
    if (safeEqual(decoded.slice(decoded.indexOf(':') + 1), PANEL_PASSWORD)) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="SingClash Panel", charset="UTF-8"').status(401).json({ error: 'نام کاربری دلخواه و رمز پنل را وارد کنید' });
}

const api = express.Router();
api.use(panelAuth);

api.get('/config', wrap(async (req, res) => {
  res.json({
    config: await getConfig(),
    publicUrl: PUBLIC_URL || null,
    storage: storageMissing() ? null : STORAGE,
  });
}));

api.put('/config', wrap(async (req, res) => {
  let next;
  try {
    next = sanitize(req.body || {}, await getConfig());
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  res.json({ config: await saveConfig(next) });
}));

api.post('/token', wrap(async (req, res) => {
  res.json({ config: await saveConfig({ ...(await getConfig()), token: newToken() }) });
}));

// Builds the output from the settings currently in the form, without saving them.
api.post('/preview', wrap(async (req, res) => {
  let cfg;
  try {
    cfg = sanitize(req.body || {}, await getConfig());
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  res.json(await generate(cfg));
}));

app.use('/api', api);
// On Vercel, public/ is served by the CDN; this covers local runs.
app.use(express.static(PUBLIC_DIR));

app.use((err, req, res, next) => {
  console.error(`[${req.method} ${req.path}]`, err);
  if (res.headersSent) return next(err);
  const msg = err.message || 'Internal error';
  if (req.path.startsWith('/api')) res.status(500).json({ error: msg });
  else res.status(500).type('text/plain').send(`Error: ${msg}`);
});

export default app;
