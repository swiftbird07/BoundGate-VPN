// The model behind the Mesh page: which nodes and tunnels exist at a moment,
// how busy the overlay was over a window, and a small force layout. Pure
// functions over the admin API's records; no DOM, so it runs in the self-test
// (scripts/mesh-selftest.ts).
import type { Node, Session, Tunnel, Role } from './types';

export type NodeKind = 'hub' | 'router' | 'exit' | 'endpoint';
export interface MeshNode {
  id: string; name: string; kind: NodeKind; roles: Role[]; node: Node;
  online: boolean; user?: string; hardware: boolean; interactive: boolean;
  r: number; x: number; y: number; vx: number; vy: number; pinned?: boolean;
}
export interface MeshLan { id: string; owner: string; prefix: string; mode: string; x: number; y: number; vx: number; vy: number }
export interface MeshEdge {
  id: string; a: string; b: string; tunnel: Tunnel; active: boolean; tcp: boolean; relay: boolean;
  rate: number;      // bytes per second, recent if known, else lifetime average
  age: number;       // seconds since it closed (history edges), 0 when active
}
export interface Mesh { nodes: MeshNode[]; lans: MeshLan[]; edges: MeshEdge[] }

const ONLINE_AFTER = 90; // seconds without a heartbeat
const REPULSION = 9000, SPRING = 230, GRAVITY = 0.006;

export function kindOf(roles: Role[]): NodeKind {
  if (roles.includes('hub')) return 'hub';
  if (roles.includes('exit-node')) return 'exit';
  if (roles.includes('subnet-router')) return 'router';
  return 'endpoint';
}
const radius: Record<NodeKind, number> = { hub: 30, exit: 24, router: 24, endpoint: 19 };

/** Was the tunnel open at time t (ms)? */
export function openAt(t: Tunnel, at: number): boolean {
  const o = Date.parse(t.opened_at);
  const c = t.closed_at ? Date.parse(t.closed_at) : Infinity;
  return o <= at && at < c;
}

/**
 * The mesh as it was at `at` (ms since epoch; `now` for live). Nodes are the
 * approved ones; who is online is only known for now (`online` is false when
 * looking back). Of several tunnels
 * between the same two nodes the open one wins, else the latest.
 * `rates` are bytes/s per tunnel id measured between two polls.
 */
export function buildMesh(nodes: Node[], sessions: Session[], tunnels: Tunnel[], at: number, now: number, windowMs: number,
                          rates: Map<string, number> = new Map(), prev?: Mesh): Mesh {
  const live = Math.abs(now - at) < 5000;
  const userOf = new Map<string, string>();
  for (const s of sessions) {
    // who was signed in at `at`: pass ended sessions too when looking back
    const end = Math.min(Date.parse(s.expires_at), s.ended_at ? Date.parse(s.ended_at) : Infinity);
    if (Date.parse(s.issued_at) <= at && at < end) userOf.set(s.node_id, s.username || s.email || s.subject);
  }
  const old = new Map<string, { x: number; y: number; vx: number; vy: number; pinned?: boolean }>();
  for (const n of prev?.nodes ?? []) old.set(n.id, n);
  for (const l of prev?.lans ?? []) old.set(l.id, l);

  const approved = nodes.filter((n) => n.status === 'approved').sort((a, b) => a.name.localeCompare(b.name));
  const hubs = approved.filter((n) => n.roles.includes('hub'));
  const spokes = approved.filter((n) => !n.roles.includes('hub'));
  const out: Mesh = { nodes: [], lans: [], edges: [] };
  approved.forEach((n) => {
    const kind = kindOf(n.roles);
    // a deterministic start: hubs on an inner ring, the rest around them
    const ring = kind === 'hub' ? 110 : 300;
    const among = kind === 'hub' ? hubs.length : approved.length - hubs.length;
    const idx = kind === 'hub' ? hubs.indexOf(n) : spokes.indexOf(n);
    const ang = (2 * Math.PI * idx) / Math.max(among, 1) + (kind === 'hub' ? 0 : 0.4);
    const p = old.get(n.id) ?? { x: Math.cos(ang) * ring, y: Math.sin(ang) * ring, vx: 0, vy: 0 };
    out.nodes.push({
      id: n.id, name: n.name, kind, roles: n.roles, node: n, r: radius[kind],
      online: live && !!n.last_seen_at && (now - Date.parse(n.last_seen_at)) / 1000 < ONLINE_AFTER,
      user: userOf.get(n.id), hardware: n.hardware_bound, interactive: n.kind === 'interactive',
      x: p.x, y: p.y, vx: p.vx, vy: p.vy, pinned: p.pinned,
    });
    for (const pf of n.prefixes ?? []) {
      const id = n.id + '|' + pf.prefix;
      const q = old.get(id) ?? { x: p.x * 1.35 + 40, y: p.y * 1.35 + 30, vx: 0, vy: 0 };
      out.lans.push({ id, owner: n.id, prefix: pf.prefix, mode: pf.mode, x: q.x, y: q.y, vx: q.vx, vy: q.vy });
    }
  });

  const known = new Set(out.nodes.map((n) => n.id));
  const best = new Map<string, MeshEdge>();
  for (const t of tunnels) {
    if (!known.has(t.hub_id) || !known.has(t.peer_id)) continue;
    const active = openAt(t, at);
    const closed = t.closed_at ? Date.parse(t.closed_at) : undefined;
    // history: closed before `at`, within the window
    if (!active && !(closed !== undefined && closed <= at && at - closed <= windowMs)) continue;
    const key = [t.hub_id, t.peer_id].sort().join('~');
    const end = closed ?? (live ? now : at);
    const secs = Math.max((Math.min(end, at) - Date.parse(t.opened_at)) / 1000, 1);
    const e: MeshEdge = {
      id: key, a: t.hub_id, b: t.peer_id, tunnel: t, active, tcp: t.transport === 'tcp', relay: t.transport === 'relay',
      rate: live && active && rates.has(t.id) ? rates.get(t.id)! : (t.bytes_in + t.bytes_out) / secs,
      age: active ? 0 : (at - closed!) / 1000,
    };
    const cur = best.get(key);
    if (!cur || (e.active && !cur.active) || (e.active === cur.active && Date.parse(t.opened_at) > Date.parse(cur.tunnel.opened_at))) best.set(key, e);
  }
  out.edges = [...best.values()];
  return out;
}

/**
 * Bytes per second per open tunnel, from two polls. Hubs report counters every
 * few seconds, not on every poll: without a new report the rate known so far
 * stands, so the picture does not flicker between a burst and nothing.
 */
export function measureRates(before: Tunnel[], after: Tunnel[], known: Map<string, number> = new Map()): Map<string, number> {
  const prev = new Map(before.map((t) => [t.id, t]));
  const out = new Map<string, number>();
  for (const t of after) {
    const was = prev.get(t.id);
    if (t.closed_at || !was) continue;
    const dt = (Date.parse(t.last_report_at) - Date.parse(was.last_report_at)) / 1000;
    if (dt <= 0) { if (known.has(t.id)) out.set(t.id, known.get(t.id)!); continue; }
    out.set(t.id, Math.max(t.bytes_in + t.bytes_out - was.bytes_in - was.bytes_out, 0) / dt);
  }
  return out;
}

/** How many tunnels were open in each of `buckets` slices of [from, to]. */
export function activity(tunnels: Tunnel[], from: number, to: number, buckets: number): number[] {
  const out = new Array<number>(buckets).fill(0);
  const step = (to - from) / buckets;
  for (const t of tunnels) {
    const o = Date.parse(t.opened_at), c = t.closed_at ? Date.parse(t.closed_at) : to;
    const first = Math.max(Math.floor((o - from) / step), 0), last = Math.min(Math.floor((c - from) / step), buckets - 1);
    for (let i = first; i <= last; i++) out[i]++;
  }
  return out;
}

/** Tunnel ids that opened or closed between two meshes (for the pulse). */
export function changes(before: Mesh | undefined, after: Mesh): { opened: string[]; closed: string[] } {
  if (!before) return { opened: [], closed: [] };
  const was = new Map(before.edges.map((e) => [e.id, e.active]));
  const opened: string[] = [], closed: string[] = [];
  for (const e of after.edges) {
    const w = was.get(e.id);
    if (e.active && w !== true) opened.push(e.id);
    if (!e.active && w === true) closed.push(e.id);
  }
  return { opened, closed };
}

/**
 * One step of the layout: nodes repel each other, tunnels and LAN links pull
 * like springs, everything drifts to the centre. Returns the energy left, so
 * the caller can stop animating when the picture is still.
 */
export function step(m: Mesh, alpha: number): number {
  type P = { x: number; y: number; vx: number; vy: number; pinned?: boolean; r?: number; kind?: NodeKind };
  const pts: P[] = [...m.nodes, ...m.lans];
  // hubs carry more charge: two hubs that share all their spokes would otherwise sit on top of each other
  const charge = (p: P) => (p.kind === 'hub' ? 3.2 : p.r ? 1.4 : 0.8);
  for (let i = 0; i < pts.length; i++) {
    for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i], b = pts[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { dx = (i % 2 ? 1 : -1) * (1 + j); dy = 1 + i; d2 = dx * dx + dy * dy; }
      const d = Math.sqrt(d2);
      let f = Math.min((REPULSION * charge(a) * charge(b) * alpha) / d2, 24);
      // labels need room: inside this distance the push does not fade with alpha
      const room = (a.r ?? 34) + (b.r ?? 34) + 56;
      if (d < room) f += (room - d) * 0.12;
      a.vx -= (dx / d) * f; a.vy -= (dy / d) * f; b.vx += (dx / d) * f; b.vy += (dy / d) * f;
    }
  }
  const at = new Map<string, P>(m.nodes.map((n) => [n.id, n]));
  const spring = (a: P | undefined, b: P | undefined, len: number, k: number) => {
    if (!a || !b) return;
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.max(Math.hypot(dx, dy), 1);
    const f = (d - len) * k * alpha;
    a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
  };
  for (const e of m.edges) spring(at.get(e.a), at.get(e.b), e.active ? SPRING : SPRING * 1.3, e.active ? 0.05 : 0.015);
  for (const l of m.lans) spring(at.get(l.owner), l, 120, 0.12);
  let energy = 0;
  for (const p of pts) {
    p.vx -= p.x * GRAVITY * alpha; p.vy -= p.y * GRAVITY * alpha;
    p.vx *= 0.82; p.vy *= 0.82;
    if (p.pinned) { p.vx = 0; p.vy = 0; continue; }
    const v = Math.hypot(p.vx, p.vy);
    if (v > 36) { p.vx *= 36 / v; p.vy *= 36 / v; } // nothing gets flung out of the picture
    p.x += p.vx; p.y += p.vy;
    energy += p.vx * p.vx + p.vy * p.vy;
  }
  return energy;
}

export function fmtRate(bps: number): string {
  const bits = bps * 8;
  if (bits < 1000) return bits < 1 ? 'idle' : `${bits.toFixed(0)} bit/s`;
  if (bits < 1e6) return `${(bits / 1e3).toFixed(bits < 1e4 ? 1 : 0)} kbit/s`;
  if (bits < 1e9) return `${(bits / 1e6).toFixed(bits < 1e7 ? 1 : 0)} Mbit/s`;
  return `${(bits / 1e9).toFixed(1)} Gbit/s`;
}
