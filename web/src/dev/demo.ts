// Demo data for UI work: `npm run dev`, then open /?demo (or ?demo=login,
// ?demo=passkey, ?demo=first, ?demo=off). Answers /api/v1 from memory so the
// console can be designed without a control plane, an IdP or a passkey.
// main.ts loads this in dev builds only; production bundles do not contain it.
import type * as T from '../lib/types';

const KEY = 'bg_demo';
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const fp = (seed: string) => 'SHA256:' + btoa(seed.repeat(8)).replace(/[^A-Za-z0-9]/g, '').slice(0, 43);

function node(i: number, name: string, status: T.Node['status'], roles: T.Role[], o: Partial<T.Node> = {}): T.Node {
  const approved = status === 'approved';
  return {
    id: `n${i}f3a9c2e7b1d04a5${i}`, name, hostname: name + '.lab', platform: 'linux/arm64', key_kind: 'softkey', hardware_bound: false,
    spki: fp(name + 'spki'), fingerprint: fp(name), status, kind: 'workload', requested_roles: roles, requested_prefixes: [], roles: status === 'pending' ? [] : roles, prefixes: [],
    overlay_ip: status === 'pending' ? undefined : `10.21.0.${i + 1}`, key_version: 1, signed: approved, signed_by: approved ? 'martin@yubikey-5c' : undefined, signed_at: approved ? ago(86400 * 3) : undefined,
    requested_at: ago(86400 * 3 + 600), request_ip: '172.30.0.' + (10 + i), confirmed_at: status === 'pending' ? undefined : ago(86400 * 3 + 300), confirmed_by: 'martin',
    approved_at: approved ? ago(86400 * 3) : undefined, approved_by: approved ? 'martin' : undefined, last_seen_at: approved ? ago(4 + i * 3) : undefined, snapshot_version: 212, active_tunnels: 0, ...o,
  };
}

const nodes: T.Node[] = [
  node(1, 'hub1', 'approved', ['hub', 'exit-node'], { public_addr: 'hub1.example.net:443', active_tunnels: 3, prefixes: [{ prefix: '10.60.0.0/24', mode: 'routed' }] }),
  node(2, 'hub2', 'approved', ['hub'], { public_addr: 'hub2.example.net:443', active_tunnels: 3 }),
  node(3, 'node-r', 'approved', ['subnet-router'], { prefixes: [{ prefix: '192.168.178.0/24', mode: 'snat' }], active_tunnels: 2 }),
  node(4, 'node-a', 'approved', ['endpoint'], { kind: 'interactive', active_tunnels: 2 }),
  node(5, 'martins-macbook', 'approved', ['endpoint'], { kind: 'interactive', platform: 'darwin/arm64', active_tunnels: 2 }),
  node(6, 'build-runner-07', 'confirmed', ['endpoint'], { key_kind: 'tpm2', hardware_bound: true, hardware_claimed: true, requested_at: ago(5400), confirmed_at: ago(1800) }),
  node(7, 'lenas-thinkpad', 'pending', ['endpoint'], { kind: 'interactive', platform: 'linux/amd64', key_kind: 'tpm2', hardware_bound: false, hardware_claimed: true, requested_at: ago(420) }),
  node(8, 'old-laptop', 'revoked', ['endpoint'], { kind: 'interactive', revoked_at: ago(86400 * 9), revoked_by: 'martin', overlay_ip: '10.21.0.31' }),
];
nodes[5].sign_command = `boundgatectl admin sign --control https://control.example.net --node ${nodes[5].id} --fingerprint ${nodes[5].fingerprint} --token st_4be1c0a97d`;
nodes[5].sign_expires_at = new Date(Date.now() + 480e3).toISOString();

const tunnel = (i: number, hub: T.Node, peer: T.Node, opened: number, closed?: number, reason?: string): T.Tunnel => ({
  id: `t${i}`, hub_id: hub.id, hub_name: hub.name, peer_id: peer.id, peer_name: peer.name, peer_addr: `203.0.113.${20 + i}:5${1000 + i * 37}`, transport: i % 5 === 3 ? 'tcp' : 'quic', opened_at: ago(opened),
  closed_at: closed === undefined ? undefined : ago(closed), close_reason: reason, bytes_in: 48_000_000 * (i + 1), bytes_out: 310_000_000 * (i + 1), packets_in: 52_000 * (i + 1), packets_out: 240_000 * (i + 1), last_report_at: ago(closed ?? 6),
});
const tunnels: T.Tunnel[] = [
  tunnel(1, nodes[0], nodes[3], 7200), tunnel(2, nodes[0], nodes[4], 3100), tunnel(3, nodes[0], nodes[2], 86000),
  tunnel(4, nodes[1], nodes[3], 7190), tunnel(5, nodes[1], nodes[4], 3090), tunnel(6, nodes[1], nodes[2], 85000),
  tunnel(7, nodes[0], nodes[7], 86400 * 9 + 4000, 86400 * 9, 'peer revoked'), tunnel(8, nodes[0], nodes[3], 90000, 7300, 'hub restarted'),
];

const sessions: T.Session[] = [
  { id: 's1', node_id: nodes[3].id, node_name: nodes[3].name, subject: 'u-ada', email: 'ada@example.net', username: 'ada', groups: ['staff', 'engineering'], login_ip: '203.0.113.21', issued_at: ago(7000), expires_at: new Date(Date.now() + 21_000e3).toISOString() },
  { id: 's2', node_id: nodes[4].id, node_name: nodes[4].name, subject: 'u-martin', email: 'martin@example.net', username: 'martin', groups: ['staff', 'boundgate-admins'], login_ip: '203.0.113.22', issued_at: ago(3000), expires_at: new Date(Date.now() + 25_000e3).toISOString() },
  { id: 's3', node_id: nodes[7].id, node_name: nodes[7].name, subject: 'u-lena', email: 'lena@example.net', username: 'lena', groups: ['staff'], issued_at: ago(86400 * 10), expires_at: ago(86400 * 9.6), ended_at: ago(86400 * 9), ended_by: 'martin', end_reason: 'node revoked' },
];

const policies: T.Policy[] = [
  { id: 'p1', name: 'staff-to-intranet', description: 'Staff reach the intranet behind hub1', enabled: true, scope: [], created_at: ago(86400 * 6), created_by: 'martin', updated_at: ago(86400 * 2), updated_by: 'martin',
    cedar: 'permit(\n  principal in BoundGate::Group::"staff",\n  action,\n  resource in BoundGate::Network::"10.60.0.0/24"\n);' },
  { id: 'p2', name: 'engineering-home-lan', description: 'Engineering may use the LAN behind node-r, HTTPS only', enabled: true, scope: [nodes[2].id], created_at: ago(86400 * 5), created_by: 'martin', updated_at: ago(86400 * 5),
    cedar: 'permit(\n  principal in BoundGate::Group::"engineering",\n  action,\n  resource in BoundGate::Network::"192.168.178.0/24"\n) when {\n  resource.port == 443\n};' },
  { id: 'p3', name: 'block-telemetry', description: 'Never allow the telemetry hosts, whoever asks', enabled: true, scope: [], created_at: ago(86400 * 4), created_by: 'ada', updated_at: ago(86400),
    cedar: 'forbid(principal, action, resource) when {\n  resource has sni && resource.sni like "*.telemetry.example.com"\n};' },
  { id: 'p4', name: 'contractors-draft', description: 'Not live yet', enabled: false, scope: [], created_at: ago(7200), created_by: 'martin', updated_at: ago(7200),
    cedar: 'permit(\n  principal in BoundGate::Group::"contractors",\n  action,\n  resource == BoundGate::Host::"10.60.0.10"\n);' },
];

let seq = 9000;
const log = (s: number, stream: string, actor: string, message: string, attrs: Record<string, unknown> = {}, device?: string): T.LogEvent => ({ id: seq--, ts: ago(s), stream, actor, device_id: device, message, attrs });
const audit: T.LogEvent[] = [
  log(420, 'enrollment', 'node', 'enrollment requested', { name: 'lenas-thinkpad', src: '198.51.100.7' }, nodes[6].id),
  log(1800, 'audit', 'martin', 'node confirmed', { name: 'build-runner-07', roles: ['endpoint'] }, nodes[5].id),
  log(3000, 'user-auth', 'martin', 'login ok', { username: 'martin', src: '203.0.113.22' }, nodes[4].id),
  log(86400, 'audit', 'ada', 'policy updated', { name: 'block-telemetry' }),
  log(86400 * 2, 'audit', 'martin', 'policy updated', { name: 'staff-to-intranet' }),
  log(86400 * 3, 'audit', 'martin', 'binding signed', { name: 'martins-macbook', signer: 'martin@yubikey-5c' }, nodes[4].id),
  log(86400 * 9, 'audit', 'martin', 'node revoked', { name: 'old-laptop' }, nodes[7].id),
];
const flow = (s: number, n: T.Node, user: string, dst: string, decision: 'allow' | 'deny', extra: Record<string, unknown> = {}): T.LogEvent =>
  log(s, 'flow', 'node', decision === 'deny' ? 'deny' : 'open', { event: decision === 'deny' ? 'deny' : 'open', node_name: nodes[0].name, principal_name: n.name, user, src: `${n.overlay_ip}:51${s % 900}`, dst, proto: 'tcp', decision, policies: decision === 'deny' ? ['block-telemetry'] : ['staff-to-intranet'], ...extra }, nodes[0].id);
const flows: T.LogEvent[] = [
  flow(12, nodes[3], 'ada', '10.60.0.10:443', 'allow', { sni: 'intranet.example.net', bytes_in: 18233, bytes_out: 942 }),
  flow(40, nodes[4], 'martin', '10.60.0.10:22', 'allow'),
  flow(95, nodes[3], 'ada', '10.60.0.44:443', 'deny', { sni: 'eu.telemetry.example.com' }),
  flow(300, nodes[4], 'martin', '192.168.178.20:443', 'allow', { sni: 'nas.home', policies: ['engineering-home-lan'] }),
  flow(1900, nodes[3], 'ada', '10.60.0.44:443', 'deny', { sni: 'us.telemetry.example.com' }),
];

const passkeys: T.Passkey[] = [
  { id: 'k1', subject: 'u-martin', email: 'martin@example.net', label: 'YubiKey 5C', status: 'active', created_at: ago(86400 * 12), approved_at: ago(86400 * 12), approved_by: 'bootstrap', last_used_at: ago(900) },
  { id: 'k2', subject: 'u-martin', email: 'martin@example.net', label: 'MacBook Touch ID', status: 'active', created_at: ago(86400 * 8), approved_at: ago(86400 * 8), approved_by: 'ada', last_used_at: ago(86400) },
  { id: 'k3', subject: 'u-ada', email: 'ada@example.net', label: 'Titan key', status: 'pending', created_at: ago(1500) },
];
const tokens: T.ApiToken[] = [
  { id: 'a1', name: 'lab scripts', created_by: 'martin', created_at: ago(86400 * 2), expires_at: new Date(Date.now() + 86400e3 * 28).toISOString(), last_used_at: ago(30) },
  { id: 'a2', name: 'terraform (old)', created_by: 'ada', created_at: ago(86400 * 40), revoked_at: ago(86400 * 11), revoked_by: 'martin' },
];
const signers: T.Signer[] = [
  { id: 'g1', name: 'martin@yubikey-5c', subject: 'u-martin', public_key: 'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIDemoDemoDemoDemoDemo martin@yubikey-5c', key_type: 'sk-ssh-ed25519@openssh.com', hardware: true, fingerprint: fp('signer1'), created_at: ago(86400 * 12), active: true },
  { id: 'g2', name: 'ada@yubikey-nano', subject: 'u-ada', public_key: 'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAdaDemoAdaDemoAdaDemo ada@yubikey-nano', key_type: 'sk-ssh-ed25519@openssh.com', hardware: true, fingerprint: fp('signer2'), created_at: ago(86400 * 8), active: true },
];

function status(mode: string): T.AuthStatus {
  const base = { own_passkeys: 0, own_pending: 0, total_passkeys: 3, bootstrap_active: false, oidc_configured: true, passkeys_enabled: true, rp_id: 'localhost' };
  if (mode === 'login') return { level: 'none', ...base };
  if (mode === 'first') return { level: 'none', ...base, total_passkeys: 0, bootstrap_active: true };
  if (mode === 'passkey') return { level: 'oidc_only', subject: 'u-martin', email: 'martin@example.net', name: 'Martin Example', via: 'session', ...base, own_passkeys: 2 };
  return { level: 'full', subject: 'u-martin', email: 'martin@example.net', name: 'Martin Example', via: 'session', ...base, own_passkeys: 2 };
}

function answer(method: string, path: string, query: URLSearchParams, body: any, mode: string): unknown {
  const count = (s: string) => nodes.filter((n) => n.status === s).length;
  if (path === '/admin/auth/status') return status(mode);
  if (path === '/admin/overview') return { nodes: { pending: count('pending'), confirmed: count('confirmed'), approved: count('approved'), revoked: count('revoked') }, active_sessions: 2, active_tunnels: 6, policies: policies.length, policies_enabled: 3, denied_last_24h: 2, pending_passkeys: 1, signers: signers.length, snapshot_version: 212 } satisfies T.Overview;
  if (path === '/admin/nodes') return query.get('state') ? nodes.filter((n) => n.status === query.get('state')) : nodes;
  const m = path.match(/^\/admin\/nodes\/([^/]+)(\/confirm)?$/);
  if (m) {
    const n = nodes.find((x) => x.id === m[1]) ?? nodes[0];
    if (method === 'DELETE') { n.status = 'revoked'; return undefined; }
    if (method !== 'GET') Object.assign(n, body ?? {}, m[2] ? { status: 'confirmed', sign_command: nodes[5].sign_command, sign_expires_at: nodes[5].sign_expires_at } : {});
    return n;
  }
  if (path === '/admin/tunnels') return tunnels.filter((t) => !query.get('active') || !t.closed_at);
  if (path === '/admin/sessions') return sessions.filter((s) => query.get('all') || !s.ended_at);
  if (path === '/admin/policies') return method === 'GET' ? policies : { ...policies[0], ...body, id: 'p' + (policies.length + 1) };
  if (path.startsWith('/admin/policies/validate')) return { ok: true };
  if (path.startsWith('/admin/policies/')) return { ...(policies.find((p) => path.endsWith(p.id)) ?? policies[0]), ...(body ?? {}) };
  if (path === '/admin/acl/evaluate') {
    const deny = String(body?.sni ?? '').includes('telemetry');
    return { allow: !deny, policies: [deny ? 'block-telemetry' : body?.draft?.name || 'staff-to-intranet'], reasons: [deny ? 'forbid matched: block-telemetry' : 'permit matched'], policy_count: 3, principal: 'node-a', user: 'ada', groups: ['staff', 'engineering'] } satisfies T.Evaluation;
  }
  if (path === '/admin/flows') return flows.filter((f) => !query.get('decision') || f.attrs?.decision === query.get('decision'));
  if (path === '/admin/logs') return query.get('stream') === 'audit' ? audit.filter((e) => e.stream === 'audit') : audit;
  if (path === '/admin/passkeys') return passkeys;
  if (path === '/admin/tokens') return method === 'GET' ? tokens : { id: 'a3', name: body?.name, created_at: ago(0), token: 'bgapi_demo_not_a_real_token' };
  if (path === '/admin/signers/set') return { version: 1, hash: 'demo', genesis_hash: 'demo', history: [] };
  if (path === '/admin/signers') return signers;
  if (path === '/admin/identity') return { control_pin: '5c1f aa42 0702 4bc8 c981 a780 ff32 7b82 8156 9d8c 512a 53d4 8c4a 5df5 0add 4db5', spki: '5c1faa4207024bc8c981a780ff327b8281569d8c512a53d48c4a5df50add4db5' };
  if (path === '/admin/settings/network') return { pool: '10.21.0.0/16', max_age_seconds: 900, ...(body ?? {}) };
  if (path === '/admin/snapshot') return { version: 212, note: 'demo data' };
  return method === 'GET' ? [] : undefined;
}

export function installDemo(): boolean {
  const q = new URLSearchParams(location.search);
  let mode = '';
  try {
    if (q.has('demo')) q.get('demo') === 'off' ? sessionStorage.removeItem(KEY) : sessionStorage.setItem(KEY, q.get('demo') || 'full');
    mode = sessionStorage.getItem(KEY) ?? '';
  } catch { return false; }
  if (!mode) return false;
  const real = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
    if (!url.pathname.startsWith('/api/v1/')) return real(input, init);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url.pathname.endsWith('/auth/logout')) { mode = 'login'; sessionStorage.setItem(KEY, mode); }
    let body: unknown;
    try { body = init?.body ? JSON.parse(String(init.body)) : undefined; } catch { /* not json */ }
    await new Promise((r) => setTimeout(r, 120));
    const data = answer(method, url.pathname.slice('/api/v1'.length), url.searchParams, body, mode);
    return data === undefined ? new Response(null, { status: 204 }) : new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  console.info(`BoundGate demo data active (${mode}); ?demo=off returns to the real API`);
  return true;
}
