// Parses the free-form "manual configs" box: share links (vless://, vmess://, ss://, trojan://,
// hysteria2://, tuic://, anytls://, socks://), Surge-style lines (e.g. Snell), Clash YAML
// proxies and sing-box JSON outbounds — all mixed together in one text block.

import yaml from 'js-yaml';
import { convertSingbox } from './singbox-to-clash.js';

const URI_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const SURGE_RE = /^([^=#]+?)\s*=\s*(snell|ss|shadowsocks|trojan|vmess|socks5|socks5-tls|http|https|hysteria2|tuic|anytls)\s*,(.*)$/i;

function b64decode(str) {
  let s = String(str).trim().replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}

function clean(obj) {
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) delete obj[k];
    else if (typeof v === 'object' && !Array.isArray(v)) {
      clean(v);
      if (!Object.keys(v).length) delete obj[k];
    }
  }
  return obj;
}

function truthy(v) {
  return v === '1' || v === 'true' || v === 'yes';
}

function splitList(v) {
  return v ? v.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
}

function parseUrl(line) {
  const u = new URL(line);
  const q = Object.fromEntries(u.searchParams.entries());
  return {
    u,
    q,
    host: u.hostname.replace(/^\[|\]$/g, ''),
    port: u.port ? Number(u.port) : undefined,
    user: decodeURIComponent(u.username),
    pass: decodeURIComponent(u.password),
    name: u.hash ? decodeURIComponent(u.hash.slice(1)) : '',
  };
}

// Shared by vless:// and trojan:// (both follow the Xray share-link standard).
function applyXrayParams(p, q, { sniKey }) {
  const security = q.security || '';
  if (security === 'tls' || security === 'reality' || security === 'xtls') {
    if (p.type !== 'trojan') p.tls = true;
  }
  if (q.sni || q.peer) p[sniKey] = q.sni || q.peer;
  if (truthy(q.allowInsecure) || truthy(q.insecure)) p['skip-cert-verify'] = true;
  if (q.alpn) p.alpn = splitList(q.alpn);
  if (q.fp) p['client-fingerprint'] = q.fp;
  if (security === 'reality') {
    p['reality-opts'] = { 'public-key': q.pbk, 'short-id': q.sid ?? '' };
    p['client-fingerprint'] ||= 'chrome';
  }
  const net = q.type || 'tcp';
  if (net === 'ws') {
    p.network = 'ws';
    p['ws-opts'] = { path: q.path || '/', headers: q.host ? { Host: q.host } : undefined };
    const ed = (q.path || '').match(/[?&]ed=(\d+)/);
    if (ed) {
      p['ws-opts'].path = q.path.replace(/[?&]ed=\d+/, '') || '/';
      p['ws-opts']['max-early-data'] = Number(ed[1]);
      p['ws-opts']['early-data-header-name'] = 'Sec-WebSocket-Protocol';
    }
  } else if (net === 'httpupgrade') {
    p.network = 'ws';
    p['ws-opts'] = { path: q.path || '/', headers: q.host ? { Host: q.host } : undefined, 'v2ray-http-upgrade': true };
  } else if (net === 'grpc') {
    p.network = 'grpc';
    p['grpc-opts'] = { 'grpc-service-name': q.serviceName || '' };
  } else if (net === 'h2' || (net === 'http' && p.tls)) {
    p.network = 'h2';
    p['h2-opts'] = { host: splitList(q.host), path: q.path || '/' };
  } else if (net === 'xhttp' || net === 'splithttp') {
    p.network = 'xhttp';
    p['xhttp-opts'] = { path: q.path || '/', host: q.host, mode: q.mode };
  } else if (net === 'http' || (net === 'tcp' && q.headerType === 'http')) {
    p.network = 'http';
    p['http-opts'] = { path: [q.path || '/'], headers: q.host ? { Host: splitList(q.host) } : undefined };
  }
}

function parseVmess(line) {
  const body = line.slice('vmess://'.length).split('#')[0];
  let j;
  try {
    j = JSON.parse(b64decode(body));
  } catch {
    // Some providers use the Xray-style vmess://uuid@host:port?... form.
    const { q, host, port, user, name } = parseUrl(line);
    const p = { name, type: 'vmess', server: host, port, uuid: user, alterId: 0, cipher: q.encryption || 'auto', udp: true };
    applyXrayParams(p, q, { sniKey: 'servername' });
    return clean(p);
  }
  const p = {
    name: j.ps,
    type: 'vmess',
    server: j.add,
    port: Number(j.port),
    uuid: j.id,
    alterId: Number(j.aid || 0),
    cipher: j.scy || 'auto',
    udp: true,
  };
  applyXrayParams(
    p,
    {
      security: j.tls,
      sni: j.sni,
      alpn: j.alpn,
      fp: j.fp,
      type: j.net === 'tcp' && j.type === 'http' ? 'http' : j.net,
      host: j.host,
      path: j.path,
      serviceName: j.net === 'grpc' ? j.path : undefined,
      allowInsecure: j.allowInsecure ? '1' : undefined,
    },
    { sniKey: 'servername' },
  );
  return clean(p);
}

function parseVless(line) {
  const { q, host, port, user, name } = parseUrl(line);
  const p = { name, type: 'vless', server: host, port, uuid: user, flow: q.flow, udp: true };
  if (q.packetEncoding) p['packet-encoding'] = q.packetEncoding;
  if (q.encryption && q.encryption !== 'none') p.encryption = q.encryption;
  applyXrayParams(p, q, { sniKey: 'servername' });
  return clean(p);
}

function parseTrojan(line) {
  const { q, host, port, user, name } = parseUrl(line);
  const p = { name, type: 'trojan', server: host, port, password: user, udp: true };
  applyXrayParams(p, { security: 'tls', ...q }, { sniKey: 'sni' });
  return clean(p);
}

function parseSs(line) {
  let rest = line.slice('ss://'.length);
  let name = '';
  const hashAt = rest.indexOf('#');
  if (hashAt !== -1) {
    name = decodeURIComponent(rest.slice(hashAt + 1));
    rest = rest.slice(0, hashAt);
  }
  let query = '';
  const qAt = rest.indexOf('?');
  if (qAt !== -1) {
    query = rest.slice(qAt + 1);
    rest = rest.slice(0, qAt);
  }
  rest = rest.replace(/\/$/, '');
  let userinfo, hostport;
  if (rest.includes('@')) {
    // SIP002: base64(method:password)@host:port  (userinfo may also be plain/percent-encoded)
    const at = rest.lastIndexOf('@');
    userinfo = decodeURIComponent(rest.slice(0, at));
    hostport = rest.slice(at + 1);
    if (!userinfo.includes(':')) userinfo = b64decode(userinfo);
  } else {
    // Legacy: base64(method:password@host:port)
    const decoded = b64decode(rest);
    const at = decoded.lastIndexOf('@');
    userinfo = decoded.slice(0, at);
    hostport = decoded.slice(at + 1);
  }
  const ci = userinfo.indexOf(':');
  const m = hostport.match(/^\[?([^\]]+?)\]?:(\d+)$/);
  if (!m) throw new Error('invalid ss host:port');
  const p = {
    name,
    type: 'ss',
    server: m[1],
    port: Number(m[2]),
    cipher: userinfo.slice(0, ci),
    password: userinfo.slice(ci + 1),
    udp: true,
  };
  const q = Object.fromEntries(new URLSearchParams(query).entries());
  if (q.plugin) {
    const [plugin, ...opts] = q.plugin.split(';');
    const o = Object.fromEntries(opts.map((x) => (x.includes('=') ? [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)] : [x, true])));
    if (plugin === 'obfs-local' || plugin === 'simple-obfs') {
      p.plugin = 'obfs';
      p['plugin-opts'] = { mode: o.obfs || 'http', host: o['obfs-host'] };
    } else if (plugin === 'v2ray-plugin') {
      p.plugin = 'v2ray-plugin';
      p['plugin-opts'] = { mode: o.mode || 'websocket', tls: o.tls === true || undefined, host: o.host, path: o.path };
    } else if (plugin === 'shadow-tls') {
      p.plugin = 'shadow-tls';
      p['plugin-opts'] = { host: o.host, password: o.password, version: Number(o.version || 3) };
    }
  }
  return clean(p);
}

function parseHysteria2(line) {
  const { q, host, port, user, pass, name } = parseUrl(line.replace(/^hy2:\/\//i, 'hysteria2://'));
  const p = {
    name,
    type: 'hysteria2',
    server: host,
    port: port || 443,
    password: pass ? `${user}:${pass}` : user,
    sni: q.sni,
    'skip-cert-verify': truthy(q.insecure) || undefined,
    obfs: q.obfs && q.obfs !== 'none' ? q.obfs : undefined,
    'obfs-password': q['obfs-password'],
    ports: q.mport || q.ports,
    alpn: splitList(q.alpn),
    up: q.up || q.upmbps,
    down: q.down || q.downmbps,
  };
  if (q.pinSHA256) p.fingerprint = q.pinSHA256;
  return clean(p);
}

function parseHysteria(line) {
  const { q, host, port, name } = parseUrl(line);
  return clean({
    name,
    type: 'hysteria',
    server: host,
    port,
    'auth-str': q.auth,
    up: q.upmbps ? `${q.upmbps} Mbps` : q.up,
    down: q.downmbps ? `${q.downmbps} Mbps` : q.down,
    obfs: q.obfsParam || q.obfs,
    sni: q.peer || q.sni,
    alpn: splitList(q.alpn),
    protocol: q.protocol,
    'skip-cert-verify': truthy(q.insecure) || undefined,
    ports: q.mport,
  });
}

function parseTuic(line) {
  const { q, host, port, user, pass, name } = parseUrl(line);
  return clean({
    name,
    type: 'tuic',
    server: host,
    port,
    uuid: user,
    password: pass,
    'congestion-controller': q.congestion_control,
    'udp-relay-mode': q.udp_relay_mode,
    sni: q.sni,
    alpn: splitList(q.alpn),
    'skip-cert-verify': truthy(q.allow_insecure) || truthy(q.insecure) || undefined,
    'disable-sni': truthy(q.disable_sni) || undefined,
    'reduce-rtt': truthy(q.reduce_rtt) || undefined,
  });
}

function parseAnytls(line) {
  const { q, host, port, user, name } = parseUrl(line);
  return clean({
    name,
    type: 'anytls',
    server: host,
    port,
    password: user,
    sni: q.sni,
    'skip-cert-verify': truthy(q.insecure) || truthy(q.allowInsecure) || undefined,
    'client-fingerprint': q.fp,
    alpn: splitList(q.alpn),
    udp: true,
  });
}

function parseSocks(line) {
  const { host, port, user, pass, name, u } = parseUrl(line);
  let username = user;
  let password = pass;
  // Some clients encode "user:pass" as base64 in the userinfo.
  if (user && !pass) {
    try {
      const d = b64decode(user);
      if (d.includes(':')) [username, password] = [d.slice(0, d.indexOf(':')), d.slice(d.indexOf(':') + 1)];
    } catch {
      /* keep as-is */
    }
  }
  return clean({ name: name || `${u.protocol}${host}:${port}`, type: 'socks5', server: host, port, username, password, udp: true });
}

const URI_PARSERS = {
  vmess: parseVmess,
  vless: parseVless,
  trojan: parseTrojan,
  ss: parseSs,
  hysteria2: parseHysteria2,
  hy2: parseHysteria2,
  hysteria: parseHysteria,
  tuic: parseTuic,
  anytls: parseAnytls,
  socks: parseSocks,
  socks5: parseSocks,
};

export function parseUri(line) {
  const scheme = line.slice(0, line.indexOf(':')).toLowerCase();
  const parser = URI_PARSERS[scheme];
  if (!parser) throw new Error(`unsupported scheme "${scheme}://"`);
  const p = parser(line);
  if (!p.server || !p.port) throw new Error('missing server or port');
  p.name ||= `${p.type}-${p.server}:${p.port}`;
  return p;
}

// Surge-style:  My Snell = snell, 1.2.3.4, 443, psk=xxx, version=4, obfs=http, obfs-host=bing.com
export function parseSurgeLine(line) {
  const m = line.match(SURGE_RE);
  if (!m) throw new Error('not a Surge proxy line');
  const name = m[1].trim();
  const type = m[2].toLowerCase();
  const parts = m[3].split(',').map((s) => s.trim());
  const server = parts[0];
  const port = Number(parts[1]);
  const kv = {};
  const positional = [];
  for (const part of parts.slice(2)) {
    const i = part.indexOf('=');
    if (i === -1) positional.push(part);
    else kv[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim().replace(/^"|"$/g, '');
  }
  const common = {
    name,
    server,
    port,
    udp: kv['udp-relay'] ? truthy(kv['udp-relay']) : undefined,
    'skip-cert-verify': truthy(kv['skip-cert-verify']) || undefined,
  };
  let p;
  switch (type) {
    case 'snell':
      p = { ...common, type: 'snell', psk: kv.psk, version: kv.version ? Number(kv.version) : undefined };
      if (kv.obfs) p['obfs-opts'] = { mode: kv.obfs, host: kv['obfs-host'] };
      if (p.version >= 3 && p.udp === undefined) p.udp = true;
      break;
    case 'ss':
    case 'shadowsocks':
      p = { ...common, type: 'ss', cipher: kv['encrypt-method'] || kv.cipher, password: kv.password };
      if (kv.obfs) {
        p.plugin = 'obfs';
        p['plugin-opts'] = { mode: kv.obfs, host: kv['obfs-host'] };
      }
      break;
    case 'trojan':
      p = { ...common, type: 'trojan', password: kv.password, sni: kv.sni };
      if (truthy(kv.ws)) {
        p.network = 'ws';
        p['ws-opts'] = { path: kv['ws-path'] || '/', headers: kv['ws-headers'] ? parseSurgeHeaders(kv['ws-headers']) : undefined };
      }
      break;
    case 'vmess':
      p = { ...common, type: 'vmess', uuid: kv.username, alterId: 0, cipher: kv['encrypt-method'] || 'auto', servername: kv.sni };
      if (truthy(kv.tls)) p.tls = true;
      if (truthy(kv.ws)) {
        p.network = 'ws';
        p['ws-opts'] = { path: kv['ws-path'] || '/', headers: kv['ws-headers'] ? parseSurgeHeaders(kv['ws-headers']) : undefined };
      }
      break;
    case 'socks5':
    case 'socks5-tls':
      p = { ...common, type: 'socks5', username: positional[0] ?? kv.username, password: positional[1] ?? kv.password };
      if (type === 'socks5-tls') p.tls = true;
      break;
    case 'http':
    case 'https':
      p = { ...common, type: 'http', username: positional[0] ?? kv.username, password: positional[1] ?? kv.password };
      if (type === 'https') p.tls = true;
      if (kv.sni) p.sni = kv.sni;
      break;
    case 'hysteria2':
      p = { ...common, type: 'hysteria2', password: kv.password, sni: kv.sni, down: kv['download-bandwidth'] ? `${kv['download-bandwidth']} Mbps` : undefined };
      break;
    case 'tuic':
      p = { ...common, type: 'tuic', uuid: kv.uuid, password: kv.password || kv.token, sni: kv.sni, alpn: splitList(kv.alpn) };
      break;
    case 'anytls':
      p = { ...common, type: 'anytls', password: kv.password, sni: kv.sni };
      break;
  }
  if (!p.server || !p.port) throw new Error('missing server or port');
  return clean(p);
}

function parseSurgeHeaders(str) {
  const out = {};
  for (const pair of str.split('|')) {
    const i = pair.indexOf(':');
    if (i !== -1) out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
  return out;
}

function isSingboxOutbound(o) {
  return o && typeof o === 'object' && typeof o.type === 'string' && ('server_port' in o || 'tag' in o || 'peers' in o);
}

function isClashProxy(o) {
  return o && typeof o === 'object' && typeof o.type === 'string' && 'name' in o && 'server' in o;
}

// Interprets a parsed YAML/JSON document as a list of Clash proxies.
export function proxiesFromStructured(doc) {
  if (!doc || typeof doc !== 'object') return { proxies: [], skipped: [] };
  if (Array.isArray(doc.proxies)) return { proxies: doc.proxies.filter(isClashProxy), skipped: [] };
  if (Array.isArray(doc.outbounds) || Array.isArray(doc.endpoints)) return convertSingbox(doc);
  const list = Array.isArray(doc) ? doc : [doc];
  const proxies = [];
  const skipped = [];
  for (const item of list) {
    if (isClashProxy(item)) proxies.push(item);
    else if (isSingboxOutbound(item)) {
      const r = convertSingbox([item]);
      proxies.push(...r.proxies);
      skipped.push(...r.skipped);
    } else if (typeof item === 'string' && URI_RE.test(item.trim())) {
      proxies.push(parseUri(item.trim()));
    }
  }
  return { proxies, skipped };
}

/**
 * Parses the manual configs text. Returns { proxies, errors } — errors are human-readable
 * messages for lines/blocks that couldn't be understood (they never abort the whole parse).
 */
export function parseManual(text) {
  const proxies = [];
  const errors = [];
  if (!text || !text.trim()) return { proxies, errors };

  // Fast path: the whole box is one JSON/YAML document.
  try {
    const doc = yaml.load(text);
    if (doc && typeof doc === 'object') {
      const r = proxiesFromStructured(doc);
      if (r.proxies.length) {
        for (const s of r.skipped) errors.push(`نوع پشتیبانی‌نشده: ${s}`);
        return { proxies: r.proxies, errors };
      }
    }
  } catch {
    /* mixed content — fall through to line mode */
  }

  const structured = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line.startsWith('//') || line.startsWith(';')) {
      structured.push('');
      return;
    }
    const bare = line.replace(/^-\s+/, '');
    if (URI_RE.test(bare)) {
      try {
        proxies.push(parseUri(bare));
      } catch (e) {
        errors.push(`خط ${idx + 1}: ${e.message}`);
      }
      structured.push('');
    } else if (SURGE_RE.test(bare)) {
      try {
        proxies.push(parseSurgeLine(bare));
      } catch (e) {
        errors.push(`خط ${idx + 1}: ${e.message}`);
      }
      structured.push('');
    } else {
      structured.push(raw);
    }
  });

  const rest = structured.join('\n');
  if (rest.split('\n').some((l) => l.trim() && !l.trim().startsWith('#'))) {
    try {
      const r = proxiesFromStructured(yaml.load(rest));
      proxies.push(...r.proxies);
      for (const s of r.skipped) errors.push(`نوع پشتیبانی‌نشده: ${s}`);
      if (!r.proxies.length && !r.skipped.length) errors.push('بخشی از متن به‌عنوان پروکسی شناسایی نشد');
    } catch (e) {
      errors.push(`خطای YAML/JSON: ${e.reason || e.message}`);
    }
  }
  return { proxies, errors };
}
