// Self-test of src/lib/mesh.ts: node scripts/mesh-selftest.ts
import { activity, buildMesh, changes, fmtRate, kindOf, measureRates, openAt, step } from '../src/lib/mesh.ts';
import type { Node, Session, Tunnel } from '../src/lib/types.ts';

let failed = 0;
const ok = (cond: boolean, what: string) => { if (!cond) { failed++; console.error('FAIL:', what); } };
const now = Date.parse('2026-09-20T12:00:00Z');
const iso = (secsAgo: number) => new Date(now - secsAgo * 1000).toISOString();
const node = (id: string, roles: Node['roles'], o: Partial<Node> = {}): Node => ({
  id, name: id, hardware_bound: false, spki: '', fingerprint: '', status: 'approved', kind: 'workload', requested_roles: [], requested_prefixes: [],
  roles, prefixes: [], key_version: 1, signed: true, requested_at: iso(9e5), snapshot_version: 1, active_tunnels: 0, last_seen_at: iso(5), ...o,
} as Node);
const tun = (id: string, hub: string, peer: string, opened: number, closed?: number, o: Partial<Tunnel> = {}): Tunnel => ({
  id, hub_id: hub, peer_id: peer, opened_at: iso(opened), closed_at: closed === undefined ? undefined : iso(closed),
  bytes_in: 1000, bytes_out: 3000, packets_in: 1, packets_out: 1, last_report_at: iso(closed ?? 5), ...o,
} as Tunnel);

const nodes = [node('hub1', ['hub', 'exit-node']), node('hub2', ['hub'], { last_seen_at: iso(600) }), node('r', ['subnet-router'], { prefixes: [{ prefix: '192.168.178.0/24', mode: 'snat' }] }),
  node('a', ['endpoint'], { kind: 'interactive', hardware_bound: true }), node('gone', ['endpoint'], { status: 'revoked' }), node('new', ['endpoint'], { status: 'pending' })];
const sessions = [{ id: 's', node_id: 'a', subject: 'u', username: 'martin', groups: [], issued_at: iso(100), expires_at: iso(-3600) },
  { id: 'old', node_id: 'r', subject: 'u', username: 'ended', groups: [], issued_at: iso(900), expires_at: iso(-3600), ended_at: iso(10) }] as Session[];
const tunnels = [tun('t1', 'hub1', 'a', 3600), tun('t2', 'hub2', 'a', 7200, 1800, { transport: 'tcp' }), tun('t3', 'hub1', 'r', 86000),
  tun('t0', 'hub1', 'a', 9000, 4000), tun('tx', 'hub1', 'gone', 5000), tun('t4', 'hub2', 'r', 90000, 87000)];
const DAY = 86400e3;

ok(kindOf(['hub', 'exit-node']) === 'hub' && kindOf(['subnet-router']) === 'router' && kindOf(['exit-node', 'endpoint']) === 'exit' && kindOf(['endpoint']) === 'endpoint', 'kindOf');
ok(openAt(tunnels[1], now - 3000e3) && !openAt(tunnels[1], now) && !openAt(tunnels[1], now - 8000e3), 'openAt');

const live = buildMesh(nodes, sessions, tunnels, now, now, DAY, new Map([['t1', 125000]]));
ok(live.nodes.length === 4 && !live.nodes.some((n) => n.id === 'gone' || n.id === 'new'), 'only approved nodes');
ok(live.nodes.find((n) => n.id === 'hub2')!.online === false && live.nodes.find((n) => n.id === 'hub1')!.online, 'online from the heartbeat');
ok(live.nodes.find((n) => n.id === 'a')!.user === 'martin' && live.nodes.find((n) => n.id === 'r')!.user === undefined, 'users from running sessions only');
ok(live.lans.length === 1 && live.lans[0].owner === 'r', 'announced prefixes become LAN satellites');
const e = (m: typeof live, a: string, b: string) => m.edges.find((x) => x.id === [a, b].sort().join('~'));
ok(live.edges.length === 3, 'one edge per pair, none to unknown nodes: ' + live.edges.length);
ok(e(live, 'hub1', 'a')!.active && e(live, 'hub1', 'a')!.tunnel.id === 't1' && e(live, 'hub1', 'a')!.rate === 125000, 'the open tunnel wins, with the measured rate');
ok(!e(live, 'hub2', 'a')!.active && e(live, 'hub2', 'a')!.tcp && Math.round(e(live, 'hub2', 'a')!.age) === 1800, 'a closed tunnel is history');
ok(e(live, 'hub2', 'r') === undefined, 'history older than the window is left out');

const past = buildMesh(nodes, sessions, tunnels, now - 3700e3, now, DAY);
ok(e(past, 'hub2', 'a')!.active && !e(past, 'hub1', 'a')!.active && e(past, 'hub1', 'a')!.tunnel.id === 't0', 'time travel: t2 still open, t1 not yet, t0 already history');
ok(buildMesh(nodes, sessions, tunnels, now - 100e3, now, DAY).nodes.find((n) => n.id === 'r')!.user === 'ended' && past.nodes.every((n) => !n.user && !n.online), 'looking back: the session that ran then, nobody online');
const earlier = buildMesh(nodes, sessions, tunnels, now - 5000e3, now, DAY);
ok(e(earlier, 'hub1', 'a')!.active && e(earlier, 'hub1', 'a')!.tunnel.id === 't0', 'time travel picks the tunnel that was open then');

const ch = changes(past, live);
ok(ch.opened.includes('a~hub1') && ch.closed.includes('a~hub2'), 'changes: ' + JSON.stringify(ch));
ok(changes(undefined, live).opened.length === 0, 'the first picture pulses nothing');

const before = [tun('t1', 'hub1', 'a', 100, undefined, { last_report_at: iso(15) })];
const after = [tun('t1', 'hub1', 'a', 100, undefined, { bytes_in: 6000, bytes_out: 8000, last_report_at: iso(10) })];
const r = measureRates(before, after);
ok(r.get('t1') === 2000, 'rate between two reports');
ok(measureRates(after, after, r).get('t1') === 2000 && measureRates(after, after).size === 0, 'no new report: the known rate stands');
const act = activity(tunnels.filter((t) => t.id !== 'tx'), now - DAY, now, 24);
ok(act.length === 24 && act[23] === 3 && act[0] === 1 && act[12] === 1, 'activity: ' + act.join(','));

// the layout comes to rest, keeps nodes apart, keeps a pinned node where it is
const m = buildMesh(nodes, sessions, tunnels, now, now, DAY);
m.nodes[0].pinned = true; const px = m.nodes[0].x, py = m.nodes[0].y;
let energy = Infinity;
for (let i = 0; i < 400; i++) energy = step(m, Math.max(1 - i / 300, 0.05));
ok(energy < 0.5, 'layout settles: ' + energy);
ok(m.nodes[0].x === px && m.nodes[0].y === py, 'pinned node stays');
for (let i = 0; i < m.nodes.length; i++) for (let j = i + 1; j < m.nodes.length; j++) {
  ok(Math.hypot(m.nodes[i].x - m.nodes[j].x, m.nodes[i].y - m.nodes[j].y) > m.nodes[i].r + m.nodes[j].r, `nodes ${i} and ${j} overlap`);
}
ok(m.nodes.every((n) => Number.isFinite(n.x) && Math.abs(n.x) < 900 && Math.abs(n.y) < 900), 'layout stays in view');
const start = buildMesh(nodes, sessions, tunnels, now, now, DAY);
ok(new Set([...start.nodes, ...start.lans].map((q) => Math.round(q.x) + ',' + Math.round(q.y))).size === start.nodes.length + start.lans.length, 'no two nodes start on the same spot');
const again = buildMesh(nodes, sessions, tunnels, now, now, DAY, new Map(), m);
ok(again.nodes[1].x === m.nodes[1].x && again.nodes[0].pinned === true, 'positions survive a refresh');

ok(fmtRate(0) === 'idle' && fmtRate(125000) === '1.0 Mbit/s' && fmtRate(125) === '1.0 kbit/s', 'fmtRate: ' + fmtRate(125000));
if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('mesh self-test: ok');
