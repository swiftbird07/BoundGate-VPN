<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import type { LogEvent, Tunnel, Node } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import Badge from '../lib/components/Badge.svelte';
  import Attrs from '../lib/components/Attrs.svelte';
  import { bytes, duration } from '../lib/util';
  import { fail } from '../lib/toast.svelte';

  type Tab = 'audit' | 'flows' | 'tunnels';
  let tab = $state<Tab>((route.query.get('tab') as Tab) || 'audit');
  let nodes = $state<Node[]>([]);
  let node = $state(route.query.get('node') || '');
  let stream = $state('audit');
  let text = $state('');
  let decision = $state(route.query.get('decision') || '');
  let dst = $state('');
  let sni = $state('');
  let user = $state('');
  let activeOnly = $state(route.query.get('active') === '1');
  let events = $state<LogEvent[]>([]);
  let tunnels = $state<Tunnel[]>([]);
  let live = $state(true);
  const streams = ['audit', 'enrollment', 'admin-auth', 'user-auth', 'tunnel', 'system', 'flow'];
  const nodeName = (id?: string) => (id ? nodes.find((n) => n.id === id)?.name ?? id.slice(0, 8) : '');

  async function load() {
    try {
      if (!nodes.length) nodes = await admin.nodes();
      if (tab === 'audit') events = await admin.logs({ stream, node, q: text, limit: 200 });
      else if (tab === 'flows') events = await admin.flows({ node, decision, dst, sni, user, limit: 200 });
      else tunnels = await admin.tunnels({ node, active: activeOnly, limit: 200 });
    } catch (e) { fail(e); }
  }
  onMount(() => { void load(); const t = setInterval(() => live && load(), 5000); return () => clearInterval(t); });
  $effect(() => { tab; stream; node; text; decision; dst; sni; user; activeOnly; void load(); });
  function setTab(t: Tab) { tab = t; navigate(`/logs?tab=${t}${node ? '&node=' + node : ''}`, true); }
</script>

<div class="page-head">
  <div><h1>Logs</h1><div class="sub">Audit trail of the control plane, flow decisions shipped by nodes, and tunnel history reported by hubs.</div></div>
  <label class="check"><input type="checkbox" bind:checked={live} /> live</label>
</div>
<div class="tabs">
  <button class:active={tab === 'audit'} onclick={() => setTab('audit')}>Audit</button>
  <button class:active={tab === 'flows'} onclick={() => setTab('flows')}>Flows</button>
  <button class:active={tab === 'tunnels'} onclick={() => setTab('tunnels')}>Tunnels</button>
</div>

<div class="card tight row" style="margin-bottom:12px">
  <select bind:value={node}><option value="">all nodes</option>{#each nodes as n}<option value={n.id}>{n.name}</option>{/each}</select>
  {#if tab === 'audit'}
    <select bind:value={stream}>{#each streams as s}<option value={s}>{s}</option>{/each}</select>
    <input placeholder="search message" bind:value={text} />
  {:else if tab === 'flows'}
    <select bind:value={decision}><option value="">any decision</option><option value="allow">allow</option><option value="deny">deny</option><option value="local">local</option></select>
    <input class="mono" placeholder="destination" bind:value={dst} />
    <input placeholder="SNI" bind:value={sni} />
    <input placeholder="user" bind:value={user} />
  {:else}
    <label class="check"><input type="checkbox" bind:checked={activeOnly} /> active only</label>
  {/if}
  <button class="btn sm" onclick={load}>Refresh</button>
</div>

<div class="card flush table-wrap">
  {#if tab === 'tunnels'}
    <table>
      <thead><tr><th>Peer</th><th>Hub</th><th>Status</th><th>Opened</th><th>Duration</th><th class="num">In</th><th class="num">Out</th><th class="num">Packets</th></tr></thead>
      <tbody>
        {#each tunnels as t (t.id)}
          <tr>
            <td><b>{t.peer_name || t.peer_id}</b><div class="faint small mono">{t.peer_addr}{#if t.transport === 'tcp'} · over TCP{/if}</div></td>
            <td>{t.hub_name || t.hub_id}</td>
            <td>{#if t.closed_at}<Badge status="ended" label={t.close_reason || 'closed'} />{:else}<span class="badge ok pulse">open</span>{/if}</td>
            <td><Time at={t.opened_at} /></td>
            <td>{duration(t.opened_at, t.closed_at)}</td>
            <td class="num">{bytes(t.bytes_in)}</td><td class="num">{bytes(t.bytes_out)}</td><td class="num">{t.packets_in + t.packets_out}</td>
          </tr>
        {:else}<tr><td colspan="8" class="empty">No tunnels recorded.</td></tr>{/each}
      </tbody>
    </table>
  {:else if tab === 'flows'}
    <table>
      <thead><tr><th>Time</th><th>Event</th><th>Decided on</th><th>Principal</th><th>Flow</th><th>Policies</th><th class="num">Bytes</th></tr></thead>
      <tbody>
        {#each events as e (e.id)}
          {@const a = e.attrs ?? {}}
          <tr>
            <td><Time at={e.ts} /></td>
            <td><Badge status={String(a.decision ?? e.message)} label={`${e.message}${a.reset ? ' + RST' : ''}`} /></td>
            <td>{a.node_name ?? nodeName(e.device_id)}</td>
            <td>{a.principal_name ?? nodeName(String(a.principal ?? ''))}{#if a.username}<div class="faint small">{a.username}{#if Array.isArray(a.groups) && a.groups.length}&nbsp;· {a.groups.join(', ')}{/if}</div>{/if}</td>
            <td class="mono small">{a.src}:{a.sport} → {a.dst}:{a.dport} {a.proto}{#if a.sni}<div class="faint">sni {a.sni}</div>{/if}{#if a.dns_name}<div class="faint">dns {a.dns_name}</div>{/if}{#if a.owner_name}<div class="faint">owner {a.owner_name}</div>{/if}</td>
            <td>{#if Array.isArray(a.policies)}{#each a.policies as p}<span class="chip">{p}</span> {/each}{/if}{#if Array.isArray(a.errors) && a.errors.length}<div class="error small">{a.errors.join('; ')}</div>{/if}{#if a.reason}<div class="faint small">{a.reason}</div>{/if}</td>
            <td class="num">{bytes(Number(a.bytes_in ?? 0) + Number(a.bytes_out ?? 0))}</td>
          </tr>
        {:else}<tr><td colspan="7" class="empty">No flow records match.</td></tr>{/each}
      </tbody>
    </table>
  {:else}
    <table>
      <thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Node</th><th>Details</th></tr></thead>
      <tbody>
        {#each events as e (e.id)}
          <tr>
            <td><Time at={e.ts} /></td>
            <td>{e.actor || '–'}</td>
            <td><b>{e.message}</b></td>
            <td>{nodeName(e.device_id)}</td>
            <td><Attrs attrs={e.attrs} skip={['name']} /></td>
          </tr>
        {:else}<tr><td colspan="5" class="empty">No events.</td></tr>{/each}
      </tbody>
    </table>
  {/if}
</div>
