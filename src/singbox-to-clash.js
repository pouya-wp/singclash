// Converts sing-box outbounds (JSON) into Clash.Meta / Mihomo proxy objects.

const SKIP_TYPES = new Set(['direct', 'block', 'dns', 'selector', 'urltest', 'shadowtls']);

function clean(obj) {
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    if (v === undefined || v === null || v === '') delete obj[key];
    else if (Array.isArray(v) && v.length === 0) delete obj[key];
    else if (typeof v === 'object' && !Array.isArray(v)) {
      clean(v);
      if (Object.keys(v).length === 0) delete obj[key];
    }
  }
  return obj;
}

function toArray(v) {
  if (v === undefined || v === null || v === '') return [];
  return Array.isArray(v) ? v : [v];
}

// sing-box durations look like "30s", "1m", "500ms"; Mihomo usually wants plain numbers.
function durationToMs(d) {
  if (typeof d === 'number') return d;
  if (typeof d !== 'string') return undefined;
  const m = d.trim().match(/^([\d.]+)\s*(ms|s|m|h)?$/);
  if (!m) return undefined;
  const n = parseFloat(m[1]);
  const unit = m[2] || 's';
  return Math.round(n * { ms: 1, s: 1000, m: 60000, h: 3600000 }[unit]);
}

function applyTls(proxy, ob, { sniKey = 'servername', tlsFlag = true } = {}) {
  const tls = ob.tls;
  if (!tls || !tls.enabled) return;
  if (tlsFlag) proxy.tls = true;
  if (tls.server_name) proxy[sniKey] = tls.server_name;
  if (tls.insecure) proxy['skip-cert-verify'] = true;
  if (tls.alpn) proxy.alpn = toArray(tls.alpn);
  if (tls.utls?.enabled !== false && tls.utls?.fingerprint) {
    proxy['client-fingerprint'] = tls.utls.fingerprint;
  }
  if (tls.reality?.enabled) {
    proxy['reality-opts'] = {
      'public-key': tls.reality.public_key,
      'short-id': tls.reality.short_id ?? '',
    };
    // Reality in Mihomo requires a uTLS fingerprint.
    if (!proxy['client-fingerprint']) proxy['client-fingerprint'] = 'chrome';
  }
  if (tls.ech?.enabled) {
    proxy['ech-opts'] = { enable: true };
    if (tls.ech.config) proxy['ech-opts'].config = toArray(tls.ech.config).join('\n');
  }
}

function applyTransport(proxy, ob) {
  const t = ob.transport;
  if (!t || !t.type) return;
  switch (t.type) {
    case 'ws': {
      proxy.network = 'ws';
      const opts = { path: t.path || '/' };
      if (t.headers && Object.keys(t.headers).length) {
        opts.headers = {};
        for (const [k, v] of Object.entries(t.headers)) opts.headers[k] = toArray(v)[0];
      }
      if (t.max_early_data) opts['max-early-data'] = t.max_early_data;
      if (t.early_data_header_name) opts['early-data-header-name'] = t.early_data_header_name;
      proxy['ws-opts'] = opts;
      break;
    }
    case 'httpupgrade': {
      proxy.network = 'ws';
      const opts = { path: t.path || '/', 'v2ray-http-upgrade': true };
      const headers = { ...(t.headers || {}) };
      if (t.host) headers.Host = t.host;
      if (Object.keys(headers).length) {
        opts.headers = {};
        for (const [k, v] of Object.entries(headers)) opts.headers[k] = toArray(v)[0];
      }
      proxy['ws-opts'] = opts;
      break;
    }
    case 'grpc':
      proxy.network = 'grpc';
      proxy['grpc-opts'] = { 'grpc-service-name': t.service_name || '' };
      break;
    case 'http': {
      // sing-box "http" transport is HTTP/2 when TLS is on, plain HTTP/1.1 otherwise.
      const hosts = toArray(t.host);
      if (proxy.tls) {
        proxy.network = 'h2';
        proxy['h2-opts'] = { host: hosts, path: t.path || '/' };
      } else {
        proxy.network = 'http';
        const opts = { method: t.method || 'GET', path: [t.path || '/'] };
        if (hosts.length) opts.headers = { Host: hosts };
        proxy['http-opts'] = opts;
      }
      break;
    }
    default:
      proxy.network = t.type;
  }
}

function applyMultiplex(proxy, ob) {
  const m = ob.multiplex;
  if (!m || !m.enabled) return;
  proxy.smux = {
    enabled: true,
    protocol: m.protocol || 'h2mux',
    'max-connections': m.max_connections,
    'min-streams': m.min_streams,
    'max-streams': m.max_streams,
    padding: m.padding || undefined,
  };
  if (m.brutal?.enabled) {
    proxy.smux['brutal-opts'] = { enabled: true, up: m.brutal.up_mbps, down: m.brutal.down_mbps };
  }
}

function serverPorts(ports) {
  // sing-box: ["20000:30000", "443"] -> Mihomo: "20000-30000,443"
  return toArray(ports).map((p) => String(p).replace(':', '-')).join(',');
}

// With port hopping sing-box may omit server_port; Mihomo still wants a base port.
function firstPort(ports) {
  const first = toArray(ports)[0];
  return first === undefined ? undefined : Number(String(first).split(/[:-]/)[0]) || undefined;
}

function parsePluginOpts(str) {
  const out = {};
  for (const part of String(str || '').split(';')) {
    if (!part) continue;
    const i = part.indexOf('=');
    if (i === -1) out[part] = true;
    else out[part.slice(0, i)] = part.slice(i + 1);
  }
  return out;
}

function convertShadowsocks(ob, base, byTag) {
  const p = { ...base, type: 'ss', cipher: ob.method, password: ob.password };
  p.udp = ob.network !== 'tcp';
  if (ob.udp_over_tcp === true || ob.udp_over_tcp?.enabled) {
    p['udp-over-tcp'] = true;
    if (ob.udp_over_tcp?.version) p['udp-over-tcp-version'] = ob.udp_over_tcp.version;
  }
  if (ob.plugin) {
    const opts = parsePluginOpts(ob.plugin_opts);
    if (ob.plugin === 'obfs-local' || ob.plugin === 'simple-obfs') {
      p.plugin = 'obfs';
      p['plugin-opts'] = { mode: opts.obfs || 'http', host: opts['obfs-host'] };
    } else if (ob.plugin === 'v2ray-plugin') {
      p.plugin = 'v2ray-plugin';
      p['plugin-opts'] = {
        mode: opts.mode || 'websocket',
        tls: opts.tls === true || opts.tls === 'true' ? true : undefined,
        host: opts.host,
        path: opts.path,
        mux: opts.mux === undefined ? undefined : opts.mux !== '0' && opts.mux !== 'false',
      };
    }
  }
  // sing-box expresses shadow-tls as an ss outbound detoured through a shadowtls outbound.
  const stls = ob.detour && byTag.get(ob.detour);
  if (stls && stls.type === 'shadowtls') {
    p.server = stls.server;
    p.port = stls.server_port;
    p.plugin = 'shadow-tls';
    p['plugin-opts'] = {
      host: stls.tls?.server_name,
      password: stls.password,
      version: stls.version || 3,
    };
    if (stls.tls?.utls?.fingerprint) p['client-fingerprint'] = stls.tls.utls.fingerprint;
  }
  applyMultiplex(p, ob);
  return p;
}

function convertWireguard(ob, base) {
  // Legacy outbound form (sing-box < 1.11) and the newer endpoint form.
  const peer = ob.peers?.[0] || {};
  const addresses = toArray(ob.local_address || ob.address);
  const p = {
    ...base,
    type: 'wireguard',
    server: ob.server || peer.address || peer.server,
    port: ob.server_port || peer.port || peer.server_port,
    'private-key': ob.private_key,
    'public-key': ob.peer_public_key || peer.public_key,
    'pre-shared-key': ob.pre_shared_key || peer.pre_shared_key,
    reserved: ob.reserved || peer.reserved,
    mtu: ob.mtu,
    udp: true,
  };
  for (const a of addresses) {
    const ip = String(a).split('/')[0];
    if (ip.includes(':')) p.ipv6 ??= ip;
    else p.ip ??= ip;
  }
  if (peer.allowed_ips) p['allowed-ips'] = toArray(peer.allowed_ips);
  return p;
}

// Snell isn't in upstream sing-box; forks/providers that emit it don't agree on field names,
// so accept the common spellings.
function convertSnell(ob, base) {
  const p = {
    ...base,
    type: 'snell',
    psk: ob.psk ?? ob.password ?? ob.key,
    version: ob.version !== undefined ? Number(ob.version) : undefined,
    udp: ob.network !== 'tcp' && Number(ob.version || 0) >= 3 ? true : undefined,
  };
  const obfs = ob.obfs_opts || ob['obfs-opts'] || ob.obfs;
  const mode = typeof obfs === 'string' ? obfs : obfs?.mode || obfs?.type;
  if (mode && mode !== 'none') {
    p['obfs-opts'] = { mode, host: obfs?.host || ob.obfs_host || ob['obfs-host'] };
  }
  return p;
}

export function convertOutbound(ob, byTag = new Map()) {
  if (!ob || typeof ob !== 'object' || SKIP_TYPES.has(ob.type)) return null;
  const base = { name: String(ob.tag ?? `${ob.type}-${ob.server}:${ob.server_port}`), server: ob.server, port: ob.server_port };
  if (ob.detour && byTag.get(ob.detour)?.type !== 'shadowtls') base['dialer-proxy'] = ob.detour;
  let p;
  switch (ob.type) {
    case 'shadowsocks':
      p = convertShadowsocks(ob, base, byTag);
      break;
    case 'vmess':
      p = {
        ...base,
        type: 'vmess',
        uuid: ob.uuid,
        alterId: ob.alter_id || 0,
        cipher: ob.security || 'auto',
        udp: ob.network !== 'tcp',
      };
      if (ob.global_padding) p['global-padding'] = true;
      if (ob.authenticated_length) p['authenticated-length'] = true;
      if (ob.packet_encoding) p['packet-encoding'] = ob.packet_encoding;
      applyTls(p, ob);
      applyTransport(p, ob);
      applyMultiplex(p, ob);
      break;
    case 'vless':
      p = { ...base, type: 'vless', uuid: ob.uuid, flow: ob.flow, udp: ob.network !== 'tcp' };
      p['packet-encoding'] = ob.packet_encoding || undefined;
      applyTls(p, ob);
      applyTransport(p, ob);
      applyMultiplex(p, ob);
      break;
    case 'trojan':
      p = { ...base, type: 'trojan', password: ob.password, udp: ob.network !== 'tcp' };
      applyTls(p, ob, { sniKey: 'sni', tlsFlag: false });
      applyTransport(p, ob);
      applyMultiplex(p, ob);
      break;
    case 'hysteria':
      p = {
        ...base,
        type: 'hysteria',
        'auth-str': ob.auth_str || (ob.auth ? Buffer.from(ob.auth, 'base64').toString() : undefined),
        obfs: ob.obfs,
        up: ob.up_mbps ? `${ob.up_mbps} Mbps` : ob.up,
        down: ob.down_mbps ? `${ob.down_mbps} Mbps` : ob.down,
        ports: ob.server_ports ? serverPorts(ob.server_ports) : undefined,
        port: ob.server_port ?? firstPort(ob.server_ports),
        'recv-window-conn': ob.recv_window_conn,
        'recv-window': ob.recv_window,
        'disable-mtu-discovery': ob.disable_mtu_discovery || undefined,
      };
      applyTls(p, ob, { sniKey: 'sni', tlsFlag: false });
      break;
    case 'hysteria2':
      p = {
        ...base,
        type: 'hysteria2',
        password: ob.password,
        up: ob.up_mbps ? `${ob.up_mbps} Mbps` : undefined,
        down: ob.down_mbps ? `${ob.down_mbps} Mbps` : undefined,
        ports: ob.server_ports ? serverPorts(ob.server_ports) : undefined,
        port: ob.server_port ?? firstPort(ob.server_ports),
        'hop-interval': ob.hop_interval ? Math.round(durationToMs(ob.hop_interval) / 1000) : undefined,
      };
      if (ob.obfs?.type) {
        p.obfs = ob.obfs.type;
        p['obfs-password'] = ob.obfs.password;
      }
      applyTls(p, ob, { sniKey: 'sni', tlsFlag: false });
      break;
    case 'tuic':
      p = {
        ...base,
        type: 'tuic',
        uuid: ob.uuid,
        password: ob.password,
        'congestion-controller': ob.congestion_control,
        'udp-relay-mode': ob.udp_relay_mode,
        'reduce-rtt': ob.zero_rtt_handshake || undefined,
        'heartbeat-interval': ob.heartbeat ? durationToMs(ob.heartbeat) : undefined,
        'udp-over-stream': ob.udp_over_stream || undefined,
      };
      applyTls(p, ob, { sniKey: 'sni', tlsFlag: false });
      break;
    case 'anytls':
      p = {
        ...base,
        type: 'anytls',
        password: ob.password,
        'idle-session-check-interval': ob.idle_session_check_interval ? durationToMs(ob.idle_session_check_interval) / 1000 : undefined,
        'idle-session-timeout': ob.idle_session_timeout ? durationToMs(ob.idle_session_timeout) / 1000 : undefined,
        'min-idle-session': ob.min_idle_session,
        udp: true,
      };
      applyTls(p, ob, { sniKey: 'sni', tlsFlag: false });
      break;
    case 'wireguard':
      p = convertWireguard(ob, base);
      break;
    case 'snell':
      p = convertSnell(ob, base);
      break;
    case 'ssh':
      p = {
        ...base,
        type: 'ssh',
        username: ob.user,
        password: ob.password,
        'private-key': ob.private_key,
        'private-key-passphrase': ob.private_key_passphrase,
        'host-key': ob.host_key ? toArray(ob.host_key) : undefined,
        'host-key-algorithms': ob.host_key_algorithms,
      };
      if (Array.isArray(p['private-key'])) p['private-key'] = p['private-key'].join('\n');
      break;
    case 'http':
      p = { ...base, type: 'http', username: ob.username, password: ob.password };
      if (ob.tls?.enabled) {
        p.tls = true;
        p.sni = ob.tls.server_name;
        if (ob.tls.insecure) p['skip-cert-verify'] = true;
      }
      break;
    case 'socks':
      p = { ...base, type: 'socks5', username: ob.username, password: ob.password, udp: ob.network !== 'tcp' };
      break;
    default:
      return null; // unsupported (e.g. tor, ssr, naive)
  }
  return clean(p);
}

/**
 * Converts a full sing-box config (or a bare array of outbounds) to Mihomo proxies.
 * Returns { proxies, skipped, samples } — skipped holds a readable reason per dropped outbound,
 * samples a few of the dropped outbounds with secrets masked (for diagnosing new formats).
 */
export function convertSingbox(config) {
  const outbounds = Array.isArray(config)
    ? config
    : [...toArray(config?.outbounds), ...toArray(config?.endpoints)];
  const byTag = new Map(outbounds.filter((o) => o?.tag).map((o) => [o.tag, o]));
  const proxies = [];
  const skipped = [];
  const samples = [];
  for (const ob of outbounds) {
    if (!ob || SKIP_TYPES.has(ob.type)) continue;
    const p = convertOutbound(ob, byTag);
    if (p && p.server && p.port) {
      proxies.push(p);
      continue;
    }
    const why = !p ? `نوع «${ob.type}» پشتیبانی نمی‌شود` : `فیلد ${p.server ? 'server_port' : 'server'} ندارد`;
    skipped.push(`${ob.tag ?? '?'} — ${why}`);
    if (samples.length < 2) samples.push(maskSecrets(ob));
  }
  // Drop dialer-proxy references to things that aren't proxies anymore.
  const names = new Set(proxies.map((p) => p.name));
  for (const p of proxies) if (p['dialer-proxy'] && !names.has(p['dialer-proxy'])) delete p['dialer-proxy'];
  return { proxies, skipped, samples };
}

const SECRET_KEYS = /^(uuid|password|private_key|pre_shared_key|psk|auth|auth_str|public_key|short_id|token)$/;

function maskSecrets(value) {
  if (Array.isArray(value)) return value.map(maskSecrets);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEYS.test(k) && typeof v === 'string' ? '***' : maskSecrets(v)]));
}
