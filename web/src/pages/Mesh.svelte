<script lang="ts">
  // The overlay as a picture: nodes, the tunnels between them right now, and
  // what was connected at any moment of the chosen window. The model lives in
  // lib/mesh.ts; this file draws it and moves it.
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { Node, Session, Tunnel } from '../lib/types';
  import { activity, buildMesh, changes, fmtRate, kindOf, measureRates, step, type Mesh, type MeshEdge, type MeshNode, type NodeKind } from '../lib/mesh';
  import { ago, bytes, duration, when } from '../lib/util';
  import Icon from '../lib/components/Icon.svelte';

  const HOUR = 3600e3;
  const windows = [{ label: '1 h', ms: HOUR }, { label: '6 h', ms: 6 * HOUR }, { label: '24 h', ms: 24 * HOUR }, { label: '7 d', ms: 168 * HOUR }];
  const kinds: { kind: NodeKind; label: string }[] = [{ kind: 'hub', label: 'Hubs' }, { kind: 'router', label: 'Subnet routers' }, { kind: 'exit', label: 'Exit nodes' }, { kind: 'endpoint', label: 'Endpoints' }];
  const BUCKETS = 144;
  // 24-grid line glyphs, same weight as the icon set
  const glyphs = {
    hub: '<circle cx="12" cy="12" r="3.2"/><path d="M12 3v5.8M12 15.2V21M3 12h5.8M15.2 12H21M5.6 5.6l4.1 4.1M14.3 14.3l4.1 4.1M18.4 5.6l-4.1 4.1M9.7 14.3l-4.1 4.1"/>',
    router: '<path d="M3.5 12h6.5l5-6h5.5M10 12l5 6h5.5"/><circle cx="10" cy="12" r="1.6"/>',
    exit: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c3.2 3 3.2 14 0 17M12 3.5c-3.2 3-3.2 14 0 17"/>',
    laptop: '<rect x="5" y="5.5" width="14" height="9.5" rx="1.8"/><path d="M2.8 18.5h18.4"/>',
    server: '<rect x="4.5" y="4.5" width="15" height="6" rx="1.8"/><rect x="4.5" y="13.5" width="15" height="6" rx="1.8"/><path d="M8 7.5h.01M8 16.5h.01"/>',
    chip: '<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 3.5V7M14 3.5V7M10 17v3.5M14 17v3.5M3.5 10H7M3.5 14H7M17 10h3.5M17 14h3.5"/>',
  };
  const glyphOf = (n: MeshNode) => (n.kind === 'hub' ? glyphs.hub : n.kind === 'router' ? glyphs.router : n.kind === 'exit' ? glyphs.exit : n.interactive ? glyphs.laptop : glyphs.server);
  const kindLabel: Record<NodeKind, string> = { hub: 'hub', router: 'subnet router', exit: 'exit node', endpoint: 'endpoint' };

  let nodes = $state.raw<Node[]>([]);
  let sessions = $state.raw<Session[]>([]);
  let tunnels = $state.raw<Tunnel[]>([]);
  let err = $state('');
  let loaded = $state(false);
  let now = $state(Date.now());
  let at = $state<number | null>(null); // null: live
  let windowMs = $state(24 * HOUR);
  let show = $state<Record<NodeKind, boolean>>({ hub: true, router: true, exit: true, endpoint: true });
  let history = $state(true);
  let user = $state('');
  let replaying = $state(false);

  let mesh = $state.raw<Mesh>({ nodes: [], lans: [], edges: [] });
  let pos = $state.raw<Record<string, { x: number; y: number }>>({});
  let vb = $state.raw({ x: -450, y: -300, w: 900, h: 600 });
  let W = $state(900), H = $state(600);
  let pulses = $state.raw<{ key: number; edge: string; kind: 'open' | 'close' }[]>([]);
  type Pick = { type: 'node' | 'edge'; id: string };
  let hover = $state<Pick | null>(null);
  let selected = $state<Pick | null>(null);
  let svg = $state<SVGSVGElement>();
  let track = $state<HTMLDivElement>();

  // not reactive: the simulation's own bookkeeping
  let rates = new Map<string, number>();
  let alpha = 1, pulseKey = 0, lastTopo = '';
  let drag: { id: string; moved: boolean; x0: number; y0: number } | null = null;

  const live = $derived(at === null);
  const shownAt = $derived(at ?? now);
  const from = $derived(now - windowMs);

  async function load() {
    try {
      const t = Date.now();
      const [n, s, tu] = await Promise.all([admin.nodes('approved'), admin.sessions(true), admin.tunnels({ since: new Date(t - windowMs).toISOString(), limit: 5000 })]);
      rates = measureRates(tunnels, tu, rates);
      nodes = n; sessions = s; tunnels = tu; now = t; err = '';
      rebuild(loaded);
      loaded = true;
    } catch (e: any) { err = e.message; }
  }

  function rebuild(pulse: boolean) {
    const next = buildMesh(nodes.filter((n) => show[kindOf(n.roles)]), sessions, tunnels, at ?? now, now, history ? windowMs : 0, rates, mesh);
    if (pulse) {
      const c = changes(mesh, next);
      const added = [...c.opened.map((edge) => ({ key: ++pulseKey, edge, kind: 'open' as const })), ...c.closed.map((edge) => ({ key: ++pulseKey, edge, kind: 'close' as const }))];
      if (added.length) {
        pulses = [...pulses, ...added].slice(-40);
        const keys = new Set(added.map((p) => p.key));
        setTimeout(() => { pulses = pulses.filter((p) => !keys.has(p.key)); }, 2600);
      }
    }
    const topo = next.nodes.map((n) => n.id).join() + '|' + next.edges.map((e) => e.id + (e.active ? '+' : '-')).join();
    if (topo !== lastTopo) { alpha = Math.max(alpha, lastTopo ? 0.5 : 1); lastTopo = topo; }
    mesh = next;
    if (selected && !find(selected)) selected = null;
  }

  function fit(): boolean {
    const pts = [...mesh.nodes.map((n) => ({ x: n.x, y: n.y, r: n.r + 44 })), ...mesh.lans.map((l) => ({ x: l.x, y: l.y, r: 64 }))];
    if (!pts.length) return false;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const p of pts) { x0 = Math.min(x0, p.x - p.r); y0 = Math.min(y0, p.y - p.r); x1 = Math.max(x1, p.x + p.r); y1 = Math.max(y1, p.y + p.r); }
    y1 += 36; // the legend sits in the bottom left corner
    let w = Math.max(x1 - x0, 560), h = Math.max(y1 - y0, 380);
    const cx = (x0 + x1) / 2, cy = (y0 + y1) / 2, aspect = W / Math.max(H, 1);
    if (w / h < aspect) w = h * aspect; else h = w / aspect;
    const t = { x: cx - w / 2, y: cy - h / 2, w, h };
    if (Math.abs(t.x - vb.x) + Math.abs(t.y - vb.y) + Math.abs(t.w - vb.w) + Math.abs(t.h - vb.h) < 0.5) return false;
    const k = 0.14;
    vb = { x: vb.x + (t.x - vb.x) * k, y: vb.y + (t.y - vb.y) * k, w: vb.w + (t.w - vb.w) * k, h: vb.h + (t.h - vb.h) * k };
    return true;
  }

  function frame() {
    if (alpha > 0.02 || drag) {
      step(mesh, drag ? Math.max(alpha, 0.3) : alpha);
      alpha *= 0.99;
      const p: typeof pos = {};
      for (const n of mesh.nodes) p[n.id] = { x: n.x, y: n.y };
      for (const l of mesh.lans) p[l.id] = { x: l.x, y: l.y };
      pos = p;
    }
    if (!drag) fit();
    if (replaying && at !== null) {
      const next = at + windowMs / (22 * 60);
      if (next >= now) { at = null; replaying = false; } else at = next;
      rebuild(true);
    }
  }

  onMount(() => {
    void load();
    const poll = setInterval(load, 5000);
    let raf = requestAnimationFrame(function loop() { frame(); raf = requestAnimationFrame(loop); });
    return () => { clearInterval(poll); cancelAnimationFrame(raf); };
  });

  // ---- pointer: drag pins a node, click selects, double click lets go ----
  function toSvg(e: PointerEvent) {
    const r = svg!.getBoundingClientRect();
    return { x: vb.x + ((e.clientX - r.left) / r.width) * vb.w, y: vb.y + ((e.clientY - r.top) / r.height) * vb.h };
  }
  function grab(e: PointerEvent, n: MeshNode) {
    if (e.button !== 0) return;
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    drag = { id: n.id, moved: false, x0: e.clientX, y0: e.clientY };
    e.stopPropagation();
  }
  function move(e: PointerEvent, n: MeshNode) {
    if (!drag || drag.id !== n.id) return;
    if (!drag.moved && Math.hypot(e.clientX - drag.x0, e.clientY - drag.y0) < 4) return;
    drag.moved = true;
    const p = toSvg(e);
    n.x = p.x; n.y = p.y; n.pinned = true;
    alpha = Math.max(alpha, 0.3);
  }
  function release(n: MeshNode) {
    if (!drag || drag.id !== n.id) return;
    if (!drag.moved) selected = selected?.type === 'node' && selected.id === n.id ? null : { type: 'node', id: n.id };
    drag = null;
  }
  function letGo(n: MeshNode) { n.pinned = false; alpha = Math.max(alpha, 0.4); }
  function relayout() {
    for (const n of mesh.nodes) n.pinned = false;
    alpha = 1;
  }
  function nodeKey(e: KeyboardEvent, n: MeshNode) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selected = { type: 'node', id: n.id }; }
    if (e.key === 'Escape') selected = null;
  }

  // ---- time ----
  function scrubTo(clientX: number) {
    const r = track!.getBoundingClientRect();
    const f = Math.min(Math.max((clientX - r.left) / r.width, 0), 1);
    replaying = false;
    at = f > 0.994 ? null : from + f * windowMs;
    rebuild(true);
  }
  let scrubbing = false;
  function scrubDown(e: PointerEvent) { scrubbing = true; (e.currentTarget as Element).setPointerCapture(e.pointerId); scrubTo(e.clientX); }
  function scrubMove(e: PointerEvent) { if (scrubbing) scrubTo(e.clientX); }
  function scrubKey(e: KeyboardEvent) {
    const stepMs = windowMs / BUCKETS * (e.shiftKey ? 6 : 1);
    let t = at ?? now;
    if (e.key === 'ArrowLeft') t -= stepMs; else if (e.key === 'ArrowRight') t += stepMs; else if (e.key === 'Home') t = from; else if (e.key === 'End') t = now; else return;
    e.preventDefault();
    replaying = false;
    at = t >= now - 1000 ? null : Math.max(t, from);
    rebuild(true);
  }
  function goLive() { replaying = false; at = null; rebuild(true); }
  function replay() { replaying = true; at = from; rebuild(false); }
  function setWindow(ms: number) { windowMs = ms; if (at !== null && at < Date.now() - ms) at = null; replaying = false; void load(); }
  function toggleKind(k: NodeKind) { show[k] = !show[k]; rebuild(false); }
  function toggleHistory() { history = !history; rebuild(false); }

  // ---- what the template reads ----
  const byId = $derived(new Map(mesh.nodes.map((n) => [n.id, n])));
  const find = (p: Pick) => (p.type === 'node' ? mesh.nodes.find((n) => n.id === p.id) : mesh.edges.find((e) => e.id === p.id));
  const focus = $derived(selected ?? hover);
  const users = $derived([...new Set(mesh.nodes.map((n) => n.user).filter((u): u is string => !!u))].sort());
  // which nodes stay bright: the neighbourhood of what is pointed at, or a user's devices
  const lit = $derived.by(() => {
    const f = focus;
    if (f?.type === 'node') return new Set([f.id, ...mesh.edges.filter((e) => e.a === f.id || e.b === f.id).flatMap((e) => [e.a, e.b])]);
    if (f?.type === 'edge') { const e = mesh.edges.find((x) => x.id === f.id); return e ? new Set([e.a, e.b]) : null; }
    if (user) { const own = new Set(mesh.nodes.filter((n) => n.user === user).map((n) => n.id)); return new Set([...own, ...mesh.edges.filter((e) => e.active && (own.has(e.a) || own.has(e.b))).flatMap((e) => [e.a, e.b])]); }
    return null;
  });
  const edgeLit = (e: MeshEdge) => {
    if (!lit) return true;
    if (focus?.type === 'node') return e.a === focus.id || e.b === focus.id;
    if (focus?.type === 'edge') return e.id === focus.id;
    const own = (id: string) => byId.get(id)?.user === user;
    return own(e.a) || own(e.b);
  };
  const activeEdges = $derived(mesh.edges.filter((e) => e.active));
  const total = $derived(activeEdges.reduce((s, e) => s + e.rate, 0));
  const tcpCount = $derived(activeEdges.filter((e) => e.tcp).length);
  const onlineCount = $derived(mesh.nodes.filter((n) => n.online).length);
  const summary = $derived(`${mesh.nodes.length} nodes · ${onlineCount} online · ${activeEdges.length} tunnel${activeEdges.length === 1 ? '' : 's'}${tcpCount ? ` (${tcpCount} over TCP)` : ''} · ${fmtRate(total)}`);

  function line(e: MeshEdge) {
    const a = pos[e.a], b = pos[e.b], na = byId.get(e.a), nb = byId.get(e.b);
    if (!a || !b || !na || !nb) return null;
    // flowing dots run along the path: from the side that sends more
    const [p, q, rp, rq] = e.tunnel.bytes_in >= e.tunnel.bytes_out ? [b, a, nb.r, na.r] : [a, b, na.r, nb.r];
    const dx = q.x - p.x, dy = q.y - p.y, d = Math.max(Math.hypot(dx, dy), 1);
    if (d < rp + rq + 8) return null;
    const ux = dx / d, uy = dy / d;
    return { x1: p.x + ux * (rp + 5), y1: p.y + uy * (rp + 5), x2: q.x - ux * (rq + 5), y2: q.y - uy * (rq + 5), mx: (p.x + q.x) / 2, my: (p.y + q.y) / 2 };
  }
  const width = (e: MeshEdge) => 1.6 + Math.min(Math.log10(1 + e.rate / 2000) * 1.1, 4);
  const speed = (e: MeshEdge) => (e.rate < 1 ? 7 : Math.min(Math.max(3.6 / (1 + Math.log10(1 + e.rate / 4000)), 0.45), 5));
  const fade = (e: MeshEdge) => 0.14 + 0.5 * Math.max(1 - (e.age * 1000) / windowMs, 0);

  const act = $derived(activity(tunnels, from, now, BUCKETS));
  const actMax = $derived(Math.max(...act, 1));
  const area = $derived.by(() => {
    const y = (v: number) => 38 - (v / actMax) * 32;
    let d = `M0 40 L0 ${y(act[0])}`;
    act.forEach((v, i) => { d += ` L${i} ${y(v)} L${i + 1} ${y(v)}`; });
    return { fill: d + ` L${BUCKETS} 40 Z`, line: d.replace(/^M0 40 L/, 'M') };
  });
  const marks = $derived.by(() => {
    const out: { key: string; left: number; kind: 'open' | 'close'; title: string }[] = [];
    for (const t of tunnels) {
      const o = Date.parse(t.opened_at), c = t.closed_at ? Date.parse(t.closed_at) : NaN;
      const who = `${t.peer_name ?? t.peer_id} ⇄ ${t.hub_name ?? t.hub_id}`;
      if (o >= from) out.push({ key: t.id + 'o', left: ((o - from) / windowMs) * 100, kind: 'open', title: `${who} opened ${when(t.opened_at)}` });
      if (c >= from) out.push({ key: t.id + 'c', left: ((c - from) / windowMs) * 100, kind: 'close', title: `${who} closed ${when(t.closed_at)}${t.close_reason ? ': ' + t.close_reason : ''}` });
    }
    return out.slice(0, 600);
  });
  const head = $derived(((shownAt - from) / windowMs) * 100);
  const clock = (t: number) => new Date(t).toLocaleString([], windowMs > 24 * HOUR ? { weekday: 'short', hour: '2-digit', minute: '2-digit' } : { hour: '2-digit', minute: '2-digit', second: windowMs <= HOUR ? '2-digit' : undefined });
  const axis = $derived([0, 0.25, 0.5, 0.75].map((f) => ({ left: f * 100, label: clock(from + f * windowMs) })));

  // the card next to what is pointed at
  const card = $derived.by(() => {
    const f = focus;
    if (!f) return null;
    let x: number, y: number, off: number;
    if (f.type === 'node') {
      const n = byId.get(f.id), p = pos[f.id];
      if (!n || !p) return null;
      x = p.x; y = p.y; off = n.r + 14;
      const mine = mesh.edges.filter((e) => e.active && (e.a === n.id || e.b === n.id));
      return place(x, y, off, { node: n, edge: null as MeshEdge | null, tunnels: mine.length, rate: mine.reduce((s, e) => s + e.rate, 0) });
    }
    const e = mesh.edges.find((k) => k.id === f.id), l = e && line(e);
    if (!e || !l) return null;
    return place(l.mx, l.my, 16, { node: null as MeshNode | null, edge: e, tunnels: 0, rate: e.rate });
  });
  function place<T>(x: number, y: number, off: number, rest: T) {
    const px = ((x - vb.x) / vb.w) * W, py = ((y - vb.y) / vb.h) * H, o = (off / vb.w) * W;
    const right = px < W - 330;
    return { ...rest, left: right ? px + o : px - o, top: Math.min(Math.max(py, 90), H - 120), right };
  }
</script>

<div class="page-head">
  <div>
    <h1>Mesh</h1>
    <div class="sub">
      {#if !loaded}Loading…{:else if live}{summary}{:else}As it was {when(new Date(shownAt).toISOString())} · {activeEdges.length} tunnel{activeEdges.length === 1 ? '' : 's'} open{/if}
    </div>
  </div>
  <div class="row" style="gap:8px; flex-wrap:wrap">
    <div class="filters" role="group" aria-label="Node kinds shown">
      {#each kinds as k}<button class="tog" class:on={show[k.kind]} aria-pressed={show[k.kind]} onclick={() => toggleKind(k.kind)}>{k.label}</button>{/each}
      <button class="tog" class:on={history} aria-pressed={history} onclick={toggleHistory} title="Closed tunnels of the window, faded by age">History</button>
    </div>
    {#if users.length}
      <select bind:value={user} aria-label="Highlight a user's devices"><option value="">All users</option>{#each users as u}<option value={u}>{u}</option>{/each}</select>
    {/if}
    <button class="btn sm" onclick={relayout} title="Release pinned nodes and lay the graph out again"><Icon name="refresh" size={14} /> Re-layout</button>
  </div>
</div>
{#if err}<p class="error">{err}</p>{/if}

<div class="stage card" class:past={!live} bind:clientWidth={W} bind:clientHeight={H}>
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
  <svg bind:this={svg} viewBox="{vb.x} {vb.y} {vb.w} {vb.h}" preserveAspectRatio="none" onclick={() => (selected = null)} role="img" aria-label="Graph of nodes and tunnels">
    <defs>
      <pattern id="mesh-dots" width="28" height="28" patternUnits="userSpaceOnUse"><circle cx="14" cy="14" r="1.1" class="dot" /></pattern>
      <radialGradient id="mesh-glow"><stop offset="0" class="glow-in" /><stop offset="1" class="glow-out" /></radialGradient>
    </defs>
    <rect x={vb.x} y={vb.y} width={vb.w} height={vb.h} fill="url(#mesh-dots)" />
    <circle cx="0" cy="0" r="460" fill="url(#mesh-glow)" />

    {#each mesh.lans as l (l.id)}
      {@const p = pos[l.id]}{@const o = pos[l.owner]}
      {#if p && o}
        <g class="lan" class:dim={lit && !lit.has(l.owner)}>
          <line x1={o.x} y1={o.y} x2={p.x} y2={p.y} />
          <g transform="translate({p.x},{p.y})">
            <rect x="-62" y="-15" width="124" height="30" rx="10" />
            <text y="-1">{l.prefix}</text><text class="mode" y="10">{l.mode === 'snat' ? 'LAN · masqueraded' : 'LAN · routed'}</text>
          </g>
        </g>
      {/if}
    {/each}

    {#each mesh.edges as e (e.id)}
      {@const l = line(e)}
      {#if l}
        <!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
        <g class="edge" class:active={e.active} class:tcp={e.tcp} class:dim={!edgeLit(e)} class:hot={focus?.type === 'edge' && focus.id === e.id}
           onpointerenter={() => (hover = { type: 'edge', id: e.id })} onpointerleave={() => (hover = null)}
           onclick={(ev) => { ev.stopPropagation(); selected = selected?.id === e.id ? null : { type: 'edge', id: e.id }; }}>
          {#if e.active}
            <line class="halo" x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} stroke-width={width(e) + 7} />
            <line class="base" x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} stroke-width={width(e)} />
            <line class="flow" x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} stroke-width={width(e) + 1.4} style="animation-duration:{speed(e)}s" />
          {:else}
            <line class="gone" x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} style="opacity:{fade(e)}" />
          {/if}
          <line class="hit" x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} />
          {#if e.active && e.tcp}<g transform="translate({l.mx},{l.my})"><rect class="tag" x="-15" y="-9" width="30" height="18" rx="6" /><text class="tagtext" y="3.5">TCP</text></g>{/if}
          {#if e.active && e.relay}<g transform="translate({l.mx},{l.my})"><rect class="tag relay" x="-21" y="-9" width="42" height="18" rx="6" /><text class="tagtext relay" y="3.5">RELAY</text></g>{/if}
        </g>
      {/if}
    {/each}

    {#each pulses as p (p.key)}
      {@const e = mesh.edges.find((x) => x.id === p.edge)}{@const l = e && line(e)}
      {#if e && l}
        <g class="pulse {p.kind}">
          <line x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} />
          {#each [e.a, e.b] as id}{@const q = pos[id]}{#if q}<circle cx={q.x} cy={q.y} r={(byId.get(id)?.r ?? 20) + 4} />{/if}{/each}
        </g>
      {/if}
    {/each}

    {#each mesh.nodes as n (n.id)}
      {@const p = pos[n.id]}
      {#if p}
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <g class="node {n.kind}" class:online={n.online} class:offline={live && !n.online} class:dim={lit && !lit.has(n.id)} class:sel={selected?.type === 'node' && selected.id === n.id} class:pinned={n.pinned}
           transform="translate({p.x},{p.y})" tabindex="0" role="button" aria-label="{n.name}, {kindLabel[n.kind]}{live ? (n.online ? ', online' : ', offline') : ''}"
           onpointerdown={(e) => grab(e, n)} onpointermove={(e) => move(e, n)} onpointerup={() => release(n)} onpointercancel={() => (drag = null)}
           onclick={(e) => e.stopPropagation()} ondblclick={() => letGo(n)} onkeydown={(e) => nodeKey(e, n)}
           onpointerenter={() => { if (!drag) hover = { type: 'node', id: n.id }; }} onpointerleave={() => (hover = null)} onfocus={() => (hover = { type: 'node', id: n.id })} onblur={() => (hover = null)}>
          {#if n.online}<circle class="breath" r={n.r + 8} />{/if}
          <circle class="disc" r={n.r} />
          <g class="glyph" transform="translate({-n.r * 0.55},{-n.r * 0.55}) scale({(n.r * 1.1) / 24})">{@html glyphOf(n)}</g>
          {#if n.hardware}<g class="badge hw" transform="translate({n.r * 0.74},{-n.r * 0.74})"><circle r="8.5" /><g transform="translate(-6,-6) scale(0.5)">{@html glyphs.chip}</g></g>{/if}
          {#if n.user}<g class="badge usr" transform="translate({n.r * 0.74},{n.r * 0.74})"><circle r="8.5" /><text y="3.6">{n.user[0].toUpperCase()}</text></g>{/if}
          {#if n.kind === 'hub' && n.roles.includes('exit-node')}<g class="badge ex" transform="translate({-n.r * 0.74},{-n.r * 0.74})"><circle r="8.5" /><g transform="translate(-6,-6) scale(0.5)">{@html glyphs.exit}</g></g>{/if}
          <text class="name" y={n.r + 18}>{n.name}</text>
          {#if n.node.overlay_ip}<text class="ip" y={n.r + 32}>{n.node.overlay_ip}</text>{/if}
        </g>
      {/if}
    {/each}
  </svg>

  {#if loaded && mesh.nodes.length === 0}
    <div class="nothing"><b>No nodes to show.</b><span>{nodes.length ? 'Every kind is switched off above.' : 'Approved nodes appear here as soon as there are any.'}</span></div>
  {/if}
  {#if !live}<div class="pastflag"><Icon name="info" size={14} /> Looking back · {ago(new Date(shownAt).toISOString())}. Who was online then is not recorded.</div>{/if}

  <div class="legend" aria-hidden="true">
    <span><i class="l-flow"></i>tunnel (QUIC)</span><span><i class="l-flow tcp"></i>over TCP</span><span><i class="l-gone"></i>closed</span>
    <span><i class="l-hw"></i>hardware key</span><span><i class="l-usr"></i>signed-in user</span>
  </div>

  {#if card}
    <div class="hovercard" class:left={!card.right} class:sticky={!!selected} style="left:{card.left}px; top:{card.top}px">
      {#if card.node}
        {@const n = card.node}
        <div class="hc-head"><b>{n.name}</b>{#each n.roles as r}<span class="chip">{r}</span>{/each}</div>
        <dl>
          {#if live}<dt>Status</dt><dd><span class="lamp" class:on={n.online}></span>{n.online ? 'online' : 'offline'}{#if n.node.last_seen_at}<span class="faint"> · seen {ago(n.node.last_seen_at)}</span>{/if}</dd>{/if}
          {#if n.node.overlay_ip}<dt>Overlay IP</dt><dd class="mono">{n.node.overlay_ip}</dd>{/if}
          <dt>User</dt><dd>{n.user ?? (n.interactive ? 'nobody signed in' : 'workload, no sign-in')}</dd>
          <dt>Device key</dt><dd>{n.node.key_kind}{n.hardware ? ' · hardware-bound' : ''}</dd>
          {#if n.node.platform}<dt>Platform</dt><dd>{n.node.platform}</dd>{/if}
          {#if n.node.public_addr}<dt>Listens at</dt><dd class="mono">{n.node.public_addr}</dd>{/if}
          {#each n.node.prefixes ?? [] as pf, i}<dt>{i === 0 ? 'Announces' : ''}</dt><dd class="mono">{pf.prefix} <span class="faint">{pf.mode}</span></dd>{/each}
          <dt>Tunnels</dt><dd>{card.tunnels}{#if live && card.tunnels} · {fmtRate(card.rate)}{/if}</dd>
        </dl>
        {#if selected}<div class="hc-foot"><a href="/nodes?id={n.id}">Node details →</a><a href="/logs?tab=tunnels&node={n.id}">Tunnel history →</a>{#if n.pinned}<button class="linklike" onclick={() => letGo(n)}>Unpin</button>{/if}</div>
        {:else}<div class="hc-hint">Click to keep this open · drag to pin</div>{/if}
      {:else if card.edge}
        {@const t = card.edge.tunnel}
        <div class="hc-head"><b>{t.peer_name ?? byId.get(t.peer_id)?.name} ⇄ {t.hub_name ?? byId.get(t.hub_id)?.name}</b><span class="chip">{(t.transport || 'quic').toUpperCase()}</span></div>
        <dl>
          <dt>State</dt><dd>{#if card.edge.active}<span class="lamp on"></span>open for {duration(t.opened_at, live ? undefined : new Date(shownAt).toISOString())}{:else}closed {ago(t.closed_at)}{/if}</dd>
          <dt>Opened</dt><dd>{when(t.opened_at)}</dd>
          {#if !card.edge.active}<dt>Closed</dt><dd>{when(t.closed_at)}{#if t.close_reason}<span class="faint"> · {t.close_reason}</span>{/if}</dd><dt>Lasted</dt><dd>{duration(t.opened_at, t.closed_at)}</dd>{/if}
          {#if card.edge.active}<dt>{live ? 'Rate now' : 'Average'}</dt><dd>{fmtRate(card.rate)}</dd>{/if}
          <dt>Traffic</dt><dd>{bytes(t.bytes_in)} in · {bytes(t.bytes_out)} out</dd>
          {#if t.peer_addr}<dt>Peer address</dt><dd class="mono">{t.peer_addr}</dd>{/if}
        </dl>
        {#if selected}<div class="hc-foot"><a href="/logs?tab=tunnels&node={t.peer_id}">Tunnel history →</a></div>{/if}
      {/if}
    </div>
  {/if}
</div>

<div class="card timeline">
  <div class="tl-head">
    <div class="seg" role="group" aria-label="Window">{#each windows as w}<button class:active={windowMs === w.ms} onclick={() => setWindow(w.ms)}>{w.label}</button>{/each}</div>
    <div class="tl-clock" class:past={!live}>{live ? 'Now' : clock(shownAt)}<span class="faint">{` · peak ${actMax} tunnel${actMax === 1 ? '' : 's'}`}</span></div>
    <div class="row" style="gap:6px">
      <button class="btn sm" onclick={replay} disabled={replaying || !loaded} title="Play the window back">▶ Replay</button>
      <button class="btn sm" class:primary={live} onclick={goLive}><span class="livedot" class:on={live}></span> Live</button>
    </div>
  </div>
  <div class="track" bind:this={track} role="slider" tabindex="0" aria-label="Moment shown" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(head)} aria-valuetext={live ? 'now' : clock(shownAt)}
       onpointerdown={scrubDown} onpointermove={scrubMove} onpointerup={() => (scrubbing = false)} onpointercancel={() => (scrubbing = false)} onkeydown={scrubKey}>
    <svg viewBox="0 0 {BUCKETS} 40" preserveAspectRatio="none" aria-hidden="true"><path class="a-fill" d={area.fill} /><path class="a-line" d={area.line} /></svg>
    {#each marks as m (m.key)}<i class="mark {m.kind}" style="left:{m.left}%" title={m.title}></i>{/each}
    <div class="played" style="left:{head}%"></div>
    <div class="playhead" class:live style="left:{head}%"><span></span></div>
  </div>
  <div class="axis">{#each axis as a}<span style="left:{a.left}%">{a.label}</span>{/each}<span class="end">now</span></div>
</div>

<style>
  .stage { position: relative; padding: 0; overflow: hidden; height: clamp(440px, calc(100vh - 330px), 820px); --edge: var(--accent-line); --edge-tcp: var(--info); }
  .stage svg { display: block; width: 100%; height: 100%; touch-action: none; user-select: none; -webkit-user-select: none; }
  .stage.past { outline: 1px dashed var(--border-strong); outline-offset: -6px; }
  .dot { fill: var(--text-3); opacity: .22; }
  .glow-in { stop-color: var(--accent); stop-opacity: .07; }
  .glow-out { stop-color: var(--accent); stop-opacity: 0; }

  .edge { cursor: pointer; transition: opacity .25s; }
  .edge line { stroke-linecap: round; fill: none; }
  .edge .hit { stroke: transparent; stroke-width: 18; }
  .edge .base { stroke: var(--edge); opacity: .42; transition: stroke-width .6s; }
  .edge .halo { stroke: var(--edge); opacity: .09; transition: stroke-width .6s, opacity .2s; }
  .edge .flow { stroke: var(--edge); stroke-dasharray: 0.1 15; animation: flow linear infinite; }
  .edge.tcp .base, .edge.tcp .halo, .edge.tcp .flow { stroke: var(--edge-tcp); }
  .edge.tcp .base { stroke-dasharray: 7 6; }
  .edge .gone { stroke: var(--text-3); stroke-width: 1.4; stroke-dasharray: 2 7; }
  .edge.hot .halo, .edge:hover .halo { opacity: .24; }
  .edge.hot .gone, .edge:hover .gone { opacity: .9 !important; stroke: var(--text-2); }
  .edge.dim { opacity: .12; }
  .tag { fill: var(--panel); stroke: var(--edge-tcp); stroke-width: 1; }
  .tag.relay { stroke: var(--edge); }
  .tagtext.relay { fill: var(--text-2); }
  .tagtext { fill: var(--edge-tcp); font: 700 9px var(--font); text-anchor: middle; letter-spacing: .04em; }
  @keyframes flow { to { stroke-dashoffset: -15.1; } }

  .pulse { pointer-events: none; }
  .pulse line { stroke-linecap: round; animation: pulse-line 2.4s ease-out forwards; }
  .pulse circle { fill: none; stroke-width: 2.5; transform-box: fill-box; transform-origin: center; animation: pulse-ring 2.4s ease-out forwards; }
  .pulse.open line, .pulse.open circle { stroke: var(--ok); }
  .pulse.close line, .pulse.close circle { stroke: var(--bad); }
  @keyframes pulse-line { from { stroke-width: 14; opacity: .85; } to { stroke-width: 2; opacity: 0; } }
  @keyframes pulse-ring { from { transform: scale(1); opacity: .9; } to { transform: scale(2.1); opacity: 0; } }

  .node { cursor: grab; outline: none; transition: opacity .25s; }
  .node:active { cursor: grabbing; }
  .node .disc { fill: var(--panel-2); stroke: var(--border-strong); stroke-width: 1.6; transition: stroke .2s, fill .2s; }
  .node.hub .disc { fill: color-mix(in srgb, var(--accent) 16%, var(--panel)); stroke: var(--accent-line); stroke-width: 2.2; }
  .node.router .disc, .node.exit .disc { stroke: var(--text-2); }
  .node .glyph { fill: none; stroke: var(--text); stroke-width: 1.9; stroke-linecap: round; stroke-linejoin: round; pointer-events: none; }
  .node.offline .disc { stroke-dasharray: 3 4; fill: var(--panel); }
  .node.offline .glyph, .node.offline .name { opacity: .45; }
  .node .breath { fill: none; stroke: var(--ok); stroke-width: 1.6; opacity: .5; transform-box: fill-box; transform-origin: center; animation: breathe 3.2s ease-in-out infinite; pointer-events: none; }
  @keyframes breathe { 0%, 100% { transform: scale(.94); opacity: .55; } 50% { transform: scale(1.04); opacity: .16; } }
  .node:hover .disc, .node:focus-visible .disc, .node.sel .disc { stroke: var(--focus-border); stroke-width: 2.6; }
  .node.dim { opacity: .18; }
  .node text { text-anchor: middle; pointer-events: none; paint-order: stroke; stroke: var(--panel); stroke-width: 4px; stroke-linejoin: round; }
  .node .name { font: 650 12.5px var(--font); fill: var(--text); }
  .node .ip { font: 10.5px var(--mono); fill: var(--text-3); }
  .badge { pointer-events: none; }
  .badge circle { stroke: var(--panel); stroke-width: 2; }
  .badge.hw circle { fill: var(--accent); }
  .badge.hw g { fill: none; stroke: var(--on-accent); stroke-width: 2.2; stroke-linecap: round; }
  .badge.usr circle { fill: var(--info); }
  .badge.usr text { font: 700 10px var(--font); fill: var(--panel); stroke: none; }
  .badge.ex circle { fill: var(--panel-3); }
  .badge.ex g { fill: none; stroke: var(--text); stroke-width: 2.2; stroke-linecap: round; }

  .lan { transition: opacity .25s; pointer-events: none; }
  .lan line { stroke: var(--text-3); stroke-width: 1.2; stroke-dasharray: 1 5; stroke-linecap: round; opacity: .7; }
  .lan rect { fill: var(--panel); stroke: var(--border-strong); stroke-dasharray: 4 3; }
  .lan text { text-anchor: middle; font: 10.5px var(--mono); fill: var(--text-2); }
  .lan text.mode { font: 600 8.5px var(--font); fill: var(--text-3); letter-spacing: .04em; text-transform: uppercase; }
  .lan.dim { opacity: .18; }

  .nothing { position: absolute; inset: 0; display: grid; place-content: center; gap: 4px; text-align: center; color: var(--text-2); pointer-events: none; }
  .pastflag { position: absolute; top: 12px; left: 50%; transform: translateX(-50%); display: flex; gap: 6px; align-items: center; padding: 5px 12px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border-strong); font-size: 12.5px; color: var(--text-2); white-space: nowrap; }
  .legend { position: absolute; left: 14px; bottom: 12px; display: flex; gap: 14px; flex-wrap: wrap; font-size: 11.5px; color: var(--text-3); pointer-events: none; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .legend i { display: inline-block; }
  .l-flow { width: 22px; height: 0; border-top: 3px dotted var(--edge); }
  .l-flow.tcp { border-top-color: var(--edge-tcp); }
  .l-gone { width: 22px; height: 0; border-top: 1.5px dashed var(--text-3); }
  .l-hw, .l-usr { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); }
  .l-usr { background: var(--info); }

  .hovercard { position: absolute; z-index: 5; width: 290px; transform: translateY(-50%); padding: 12px 14px; border-radius: 12px; background: var(--panel-solid); border: 1px solid var(--border-strong); box-shadow: var(--shadow-pop); pointer-events: none; font-size: 12.5px; animation: pop .12s ease-out; }
  .hovercard.left { transform: translate(-100%, -50%); }
  .hovercard.sticky { pointer-events: auto; border-color: var(--accent-line); }
  @keyframes pop { from { opacity: 0; scale: .97; } }
  .hc-head { display: flex; flex-wrap: wrap; gap: 5px; align-items: center; margin-bottom: 8px; font-size: 13.5px; }
  .hc-head b { margin-right: 4px; }
  .hovercard dl { display: grid; grid-template-columns: auto 1fr; gap: 3px 12px; margin: 0; }
  .hovercard dt { color: var(--text-3); white-space: nowrap; }
  .hovercard dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
  .hovercard .mono { font-family: var(--mono); font-size: 11.5px; }
  .hc-foot { display: flex; gap: 14px; margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--border); font-weight: 600; }
  .hc-hint { margin-top: 8px; color: var(--text-3); font-size: 11.5px; }
  .linklike { border: 0; background: none; padding: 0; font: inherit; font-weight: 600; color: var(--link); cursor: pointer; margin-left: auto; }
  .lamp { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--text-3); margin-right: 6px; }
  .lamp.on { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 25%, transparent); }

  .filters { display: inline-flex; gap: 4px; flex-wrap: wrap; }
  .tog { border: 1px solid var(--border-strong); background: transparent; color: var(--text-3); border-radius: 999px; padding: 4px 11px; font: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer; transition: background .12s, color .12s, border-color .12s; }
  .tog.on { background: var(--accent-soft); border-color: var(--accent-line); color: var(--text); }
  .tog:hover { color: var(--text); }
  select { padding: 4px 8px; font-size: 12.5px; }

  .timeline { margin-top: 14px; padding: 12px 16px 10px; }
  .tl-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
  .tl-clock { font: 650 14px var(--display); }
  .tl-clock.past { color: var(--warn); }
  .livedot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--text-3); margin-right: 2px; }
  .livedot.on { background: var(--bad); animation: blink 1.6s ease-in-out infinite; }
  @keyframes blink { 50% { opacity: .35; } }
  .track { position: relative; height: 64px; border-radius: 10px; background: var(--bg-2); border: 1px solid var(--border); cursor: ew-resize; overflow: hidden; touch-action: none; outline: none; }
  .track:focus-visible { box-shadow: var(--focus); border-color: var(--focus-border); }
  .track svg { position: absolute; inset: 14px 0 0 0; width: 100%; height: calc(100% - 14px); }
  .a-fill { fill: var(--accent); opacity: .16; }
  .a-line { fill: none; stroke: var(--accent-line); stroke-width: 1.5; vector-effect: non-scaling-stroke; }
  .mark { position: absolute; top: 3px; width: 2px; height: 8px; border-radius: 1px; margin-left: -1px; }
  .mark.open { background: var(--ok); }
  .mark.close { background: var(--bad); top: 5px; height: 6px; opacity: .8; }
  .played { position: absolute; top: 0; bottom: 0; right: 0; background: var(--bg-2); opacity: .72; pointer-events: none; }
  .playhead { position: absolute; top: 0; bottom: 0; width: 2px; margin-left: -1px; background: var(--warn); pointer-events: none; }
  .playhead.live { background: var(--bad); }
  .playhead span { position: absolute; top: -1px; left: -4px; width: 10px; height: 10px; border-radius: 50%; background: inherit; }
  .axis { position: relative; height: 16px; margin-top: 4px; font-size: 11px; color: var(--text-3); }
  .axis span { position: absolute; top: 0; }
  .axis .end { right: 0; }

  @media (prefers-reduced-motion: reduce) {
    .edge .flow, .node .breath, .livedot.on { animation: none; }
    .edge .flow { stroke-dasharray: none; opacity: .5; }
    .pulse line, .pulse circle { animation-duration: .01s; }
  }
</style>
