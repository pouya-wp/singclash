import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import yaml from 'js-yaml';
import { convertSingbox } from '../src/singbox-to-clash.js';
import { parseManual } from '../src/manual-parser.js';
import { buildProfile, parseSubscriptionBody } from '../src/builder.js';
import { defaults } from '../src/config-store.js';

const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/singbox.json', import.meta.url)));
const byName = (list) => Object.fromEntries(list.map((p) => [p.name, p]));

test('converts every proxy outbound and skips non-proxy ones', () => {
  const { proxies, skipped } = convertSingbox(fixture);
  assert.deepEqual(skipped, []);
  assert.deepEqual(
    proxies.map((p) => p.name),
    ['🇩🇪 DE-Reality', 'NL-WS', 'FR-gRPC', 'US-HTTPUpgrade', 'SS', 'SS-STLS', 'HY2', 'TUIC', 'ANY', 'WG'],
  );
});

test('maps protocol details to Mihomo fields', () => {
  const p = byName(convertSingbox(fixture).proxies);

  assert.deepEqual(p['🇩🇪 DE-Reality'], {
    name: '🇩🇪 DE-Reality', server: 'de.example.com', port: 443, type: 'vless',
    uuid: '11111111-2222-3333-4444-555555555555', flow: 'xtls-rprx-vision', udp: true,
    'packet-encoding': 'xudp', tls: true, servername: 'www.microsoft.com', 'client-fingerprint': 'chrome',
    'reality-opts': { 'public-key': 'YYcQQgSaleSONt6Aq2QgCyA0q6ZJam5lNylqvaqEF_o', 'short-id': 'abcd' },
  });

  assert.equal(p['NL-WS'].network, 'ws');
  assert.deepEqual(p['NL-WS']['ws-opts'], {
    path: '/ws', headers: { Host: 'cdn.example.com' }, 'max-early-data': 2048, 'early-data-header-name': 'Sec-WebSocket-Protocol',
  });
  assert.equal(p['NL-WS']['skip-cert-verify'], true);

  assert.equal(p['FR-gRPC'].sni, 'fr.example.com');
  assert.equal(p['FR-gRPC'].tls, undefined);
  assert.deepEqual(p['FR-gRPC']['grpc-opts'], { 'grpc-service-name': 'grpcsvc' });

  assert.equal(p['US-HTTPUpgrade']['ws-opts']['v2ray-http-upgrade'], true);
  assert.equal(p['US-HTTPUpgrade']['ws-opts'].headers.Host, 'us.example.com');

  assert.equal(p.SS.smux.protocol, 'h2mux');
  assert.equal(p['SS-STLS'].server, '5.6.7.8');
  assert.equal(p['SS-STLS'].plugin, 'shadow-tls');
  assert.deepEqual(p['SS-STLS']['plugin-opts'], { host: 'www.apple.com', password: 'stlspw', version: 3 });
  assert.equal(p['SS-STLS']['dialer-proxy'], undefined);

  assert.equal(p.HY2.ports, '20000-30000');
  assert.equal(p.HY2['hop-interval'], 30);
  assert.equal(p.HY2.obfs, 'salamander');
  assert.equal(p.HY2['obfs-password'], 'obfspw');
  assert.equal(p.HY2.up, '50 Mbps');

  assert.equal(p.TUIC['heartbeat-interval'], 10000);
  assert.equal(p.TUIC['reduce-rtt'], true);

  assert.deepEqual(p.WG, {
    name: 'WG', type: 'wireguard', server: 'wg.example.com', port: 2408, 'private-key': '+A3O+XglE2z+SUaQyA1VktCa1Y7CgyZbrx9V6mgbTpc=', 'public-key': 'UfTdMqjCsSQzUlEnDBOkZxoJhbzZnU9H+mVkf7Wsmqs=',
    reserved: [1, 2, 3], mtu: 1280, udp: true, ip: '172.16.0.2', ipv6: 'fd01::2', 'allowed-ips': ['0.0.0.0/0', '::/0'],
  });
});

test('parses mixed manual configs (links, Surge Snell line, YAML)', () => {
  const text = `
vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443?security=reality&sni=a.com&pbk=PK&sid=01&fp=firefox&type=grpc&serviceName=svc#My%20VLESS
vmess://${Buffer.from(JSON.stringify({ v: '2', ps: 'VM', add: 'vm.com', port: '443', id: 'id', aid: '0', net: 'ws', host: 'h.com', path: '/p?ed=2048', tls: 'tls', sni: 's.com' })).toString('base64')}
ss://${Buffer.from('aes-256-gcm:pass').toString('base64')}@9.9.9.9:8388#SS%20Link
hy2://pw@hy.com:443?sni=hy.com&obfs=salamander&obfs-password=x&insecure=1#HY
Home Snell = snell, 1.2.3.4, 443, psk=secret, version=4, obfs=http, obfs-host=bing.com
# a comment
- name: my-trojan
  type: trojan
  server: t.com
  port: 443
  password: tp
`;
  const { proxies, errors } = parseManual(text);
  assert.deepEqual(errors, []);
  const p = byName(proxies);
  assert.deepEqual(Object.keys(p), ['My VLESS', 'VM', 'SS Link', 'HY', 'Home Snell', 'my-trojan']);
  assert.equal(p['My VLESS'].server, '2001:db8::1');
  assert.equal(p['My VLESS']['reality-opts']['public-key'], 'PK');
  assert.equal(p['My VLESS']['grpc-opts']['grpc-service-name'], 'svc');
  assert.deepEqual(p.VM['ws-opts'], { path: '/p', headers: { Host: 'h.com' }, 'max-early-data': 2048, 'early-data-header-name': 'Sec-WebSocket-Protocol' });
  assert.equal(p.VM.servername, 's.com');
  assert.equal(p['SS Link'].cipher, 'aes-256-gcm');
  assert.equal(p.HY['skip-cert-verify'], true);
  assert.deepEqual(p['Home Snell'], {
    name: 'Home Snell', server: '1.2.3.4', port: 443, type: 'snell', psk: 'secret', version: 4,
    'obfs-opts': { mode: 'http', host: 'bing.com' }, udp: true,
  });
  assert.equal(p['my-trojan'].password, 'tp');
});

test('manual box accepts a sing-box outbound JSON', () => {
  const { proxies } = parseManual(JSON.stringify(fixture.outbounds[3]));
  assert.equal(proxies[0].type, 'vmess');
});

test('reports unparseable manual lines without failing', () => {
  const { proxies, errors } = parseManual('foo://bar\nvless://u@h.com:443#ok');
  assert.equal(proxies.length, 1);
  assert.equal(errors.length, 1);
});

test('subscription body fallback: base64 link list', () => {
  const body = Buffer.from('trojan://pw@a.com:443#A\nss://' + Buffer.from('aes-128-gcm:x').toString('base64') + '@b.com:1#B').toString('base64');
  const r = parseSubscriptionBody(body);
  assert.equal(r.format, 'links');
  assert.equal(r.proxies.length, 2);
});

test('profile puts every proxy into the url-test group and dumps valid YAML', () => {
  const cfg = defaults();
  const { proxies } = convertSingbox(fixture);
  const doc = yaml.load(yaml.dump(buildProfile(cfg, proxies)));
  const auto = doc['proxy-groups'].find((g) => g.type === 'url-test');
  assert.equal(auto.proxies.length, proxies.length);
  assert.equal(doc.rules.at(-1), 'MATCH,PROXY');
  assert.ok(doc.rules.includes('GEOIP,IR,DIRECT'));
});

test('empty profile still produces a valid url-test group', () => {
  const doc = buildProfile(defaults(), []);
  assert.deepEqual(doc['proxy-groups'][1].proxies, ['DIRECT']);
});

test('hysteria2 with only server_ports gets a base port', () => {
  const { proxies } = convertSingbox([{ type: 'hysteria2', tag: 'hop', server: 'h.com', server_ports: ['20000:30000'], password: 'p' }]);
  assert.equal(proxies[0].port, 20000);
  assert.equal(proxies[0].ports, '20000-30000');
});

test('dropped outbounds report type/reason and a masked sample', () => {
  const r = convertSingbox([{ type: 'naive', tag: 'N', server: 'n.com', server_port: 443, password: 'secret' }, { type: 'vless', tag: 'V', uuid: 'u' }]);
  assert.equal(r.proxies.length, 0);
  assert.match(r.skipped[0], /naive/);
  assert.match(r.skipped[1], /server/);
  assert.equal(r.samples[0].password, '***');
});

test('converts Snell outbounds emitted by sing-box forks', () => {
  const { proxies, skipped } = convertSingbox([
    { type: 'snell', tag: 'S1', server: 's.com', server_port: 443, psk: 'k', version: 4, obfs_opts: { mode: 'http', host: 'bing.com' } },
    { type: 'snell', tag: 'S2', server: 's.com', server_port: 444, password: 'k', version: 2, obfs: 'tls', obfs_host: 'a.com' },
  ]);
  assert.deepEqual(skipped, []);
  assert.deepEqual(proxies[0], { name: 'S1', server: 's.com', port: 443, type: 'snell', psk: 'k', version: 4, udp: true, 'obfs-opts': { mode: 'http', host: 'bing.com' } });
  assert.deepEqual(proxies[1]['obfs-opts'], { mode: 'tls', host: 'a.com' });
  assert.equal(proxies[1].psk, 'k');
});
