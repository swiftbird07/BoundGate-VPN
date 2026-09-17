<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { Overview, Node, Tunnel, LogEvent } from '../lib/types';
  import Badge from '../lib/components/Badge.svelte';
  import Time from '../lib/components/Time.svelte';
  import { bytes } from '../lib/util';
  import { fail } from '../lib/toast.svelte';

  let ov = $state<Overview | null>(null);
  let nodes = $state<Node[]>([]);
  let tunnels = $state<Tunnel[]>([]);
  let audit = $state<LogEvent[]>([]);
  let err = $state('');
  async function load() {
    try {
      [ov, nodes, tunnels, audit] = await Promise.all([admin.overview(), admin.nodes(), admin.tunnels({ active: true, limit: 50 }), admin.logs({ stream: 'audit', limit: 8 })]);
      err = '';
    } catch (e: any) { err = e.message; }
  }
  onMount(() => { void load(); const t = setInterval(load, 10000); return () => clearInterval(t); });
  const attention = $derived(nodes.filter((n) => n.status === 'pending' || n.status === 'confirmed'));
  const online = $derived(nodes.filter((n) => n.status === 'approved' && n.last_seen_at && Date.now() - new Date(n.last_seen_at).getTime() < 90000));
</script>

<div class="page-head">
  <div><h1>Overview</h1><div class="sub">Live state of the overlay{#if ov} · snapshot v{ov.snapshot_version}{/if}</div></div>
  <button class="btn sm" onclick={load}>Refresh</button>
</div>
{#if err}<p class="error">{err}</p>{/if}
{#if ov}
  <div class="grid cols-4" style="margin-bottom:16px">
    <div class="card stat"><span class="n">{ov.nodes.approved ?? 0}</span><span class="l">approved nodes · {online.length} seen in the last 90 s</span></div>
    <div class="card stat"><span class="n">{ov.active_tunnels}</span><span class="l">active tunnels</span></div>
    <div class="card stat"><span class="n">{ov.active_sessions}</span><span class="l">user sessions</span></div>
    <div class="card stat"><span class="n">{ov.policies_enabled}<span class="faint" style="font-size:16px">/{ov.policies}</span></span><span class="l">policies enabled</span></div>
    <div class="card stat"><span class="n" style="{ov.denied_last_24h ? '' : ''}">{ov.denied_last_24h}</span><span class="l">flows denied · 24 h</span></div>
    <div class="card stat"><span class="n">{(ov.nodes.pending ?? 0) + (ov.nodes.confirmed ?? 0)}</span><span class="l">nodes awaiting approval</span></div>
    <div class="card stat"><span class="n">{ov.pending_passkeys}</span><span class="l">passkeys awaiting approval</span></div>
    <div class="card stat"><span class="n">{ov.signers}</span><span class="l">admin signing keys</span></div>
  </div>
{/if}
<div class="grid cols-2">
  <div class="card">
    <div class="card-title"><h2>Needs attention</h2><a href="/nodes">all nodes →</a></div>
    {#if attention.length === 0}
      <div class="empty">Nothing waiting. New enrollments show up here.</div>
    {:else}
      <table><thead><tr><th>Node</th><th>Status</th><th>Requested</th><th></th></tr></thead><tbody>
        {#each attention as n (n.id)}
          <tr><td><b>{n.name}</b><div class="faint small">{n.platform} · {n.kind}</div></td><td><Badge status={n.status} /></td><td><Time at={n.requested_at} /></td><td><a class="btn sm" href="/nodes?id={n.id}">Review</a></td></tr>
        {/each}
      </tbody></table>
    {/if}
  </div>
  <div class="card">
    <div class="card-title"><h2>Active tunnels</h2><a href="/logs?tab=tunnels">history →</a></div>
    {#if tunnels.length === 0}
      <div class="empty">No spoke is attached to a hub right now.</div>
    {:else}
      <table><thead><tr><th>Peer</th><th>Hub</th><th>Since</th><th class="num">Traffic</th></tr></thead><tbody>
        {#each tunnels as t (t.id)}
          <tr><td><b>{t.peer_name || t.peer_id}</b><div class="faint small">{t.peer_addr}</div></td><td>{t.hub_name || t.hub_id}</td><td><Time at={t.opened_at} /></td><td class="num">{bytes(t.bytes_in + t.bytes_out)}</td></tr>
        {/each}
      </tbody></table>
    {/if}
  </div>
  <div class="card">
    <div class="card-title"><h2>Recent admin activity</h2><a href="/logs">all logs →</a></div>
    {#if audit.length === 0}<div class="empty">No audit events yet.</div>{:else}
      <div class="timeline">
        {#each audit as e (e.id)}
          <div class="ev"><div><b>{e.message}</b> <span class="faint small">by {e.actor || '?'}</span></div><div class="faint small"><Time at={e.ts} />{#if e.attrs?.name} · {e.attrs.name}{/if}</div></div>
        {/each}
      </div>
    {/if}
  </div>
  <div class="card">
    <div class="card-title"><h2>Fleet</h2><a href="/nodes">manage →</a></div>
    <table><thead><tr><th>Node</th><th>Roles</th><th>Overlay IP</th><th>Seen</th><th class="num">Tunnels</th></tr></thead><tbody>
      {#each nodes.filter((n) => n.status === 'approved') as n (n.id)}
        <tr><td><b>{n.name}</b> <span class="faint small">{n.kind}</span></td><td>{#each n.roles as r}<span class="chip">{r}</span> {/each}</td><td class="mono">{n.overlay_ip}</td><td><Time at={n.last_seen_at} /></td><td class="num">{n.active_tunnels}</td></tr>
      {/each}
    </tbody></table>
  </div>
</div>
