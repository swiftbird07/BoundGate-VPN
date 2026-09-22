<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { Policy, Node } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import { parse, describe, highlight } from '../lib/cedar';
  import { toast, fail } from '../lib/toast.svelte';

  let policies = $state<Policy[]>([]);
  let nodes = $state<Node[]>([]);
  async function load() { try { [policies, nodes] = await Promise.all([admin.policies(), admin.nodes()]); } catch (e) { fail(e); } }
  onMount(() => { void load(); });
  const nodeName = (id: string) => nodes.find((n) => n.id === id)?.name ?? id.slice(0, 8);
  // groups are headings; the order is by name, ungrouped policies last
  const groups = $derived.by(() => {
    const m = new Map<string, Policy[]>();
    for (const p of policies) { const g = p.group || ''; if (!m.has(g)) m.set(g, []); m.get(g)!.push(p); }
    return [...m.entries()].sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)));
  });
  let closed = $state<Record<string, boolean>>((() => { try { return JSON.parse(localStorage.getItem('bg.policy.groups') || '{}'); } catch { return {}; } })());
  function fold(g: string) { closed = { ...closed, [g]: !closed[g] }; try { localStorage.setItem('bg.policy.groups', JSON.stringify(closed)); } catch { /* private mode */ } }
  async function toggle(p: Policy) {
    try { await admin.putPolicy(p.id, { name: p.name, description: p.description || '', cedar: p.cedar, enabled: !p.enabled, group: p.group || '', scope: p.scope }); toast(p.enabled ? 'Policy disabled' : 'Policy enabled', 'ok'); await load(); } catch (e) { fail(e); }
  }
  async function remove(p: Policy) {
    if (!window.confirm(`Delete policy “${p.name}”? Nodes re-evaluate their flows within seconds.`)) return;
    try { await admin.deletePolicy(p.id); toast('Deleted', 'ok'); await load(); } catch (e) { fail(e); }
  }
</script>

<div class="page-head">
  <div><h1>Access policies</h1><div class="sub">Cedar policies decide every flow. Nothing is allowed until a policy permits it; a forbid always wins.</div></div>
  <div class="row"><a class="btn" href="/lists">Lists</a><a class="btn primary" href="/policies/new">+ New policy</a></div>
</div>
{#if policies.length === 0}
  <div class="card empty">No policies: every flow in the overlay is denied. <a href="/policies/new">Write the first one.</a></div>
{/if}
{#each groups as [g, ps] (g)}
  {#if groups.length > 1 || g}
    <div class="row between" style="margin:18px 0 8px">
      <button class="btn sm ghost" onclick={() => fold(g)} style="font-size:14px" aria-expanded={!closed[g]}>
        <span style="display:inline-block;width:1em;transform:rotate({closed[g] ? 0 : 90}deg);transition:transform .15s">▸</span>
        <b>{g || 'Ungrouped'}</b> <span class="faint">· {ps.length} · {ps.filter((p) => p.enabled).length} enabled</span>
      </button>
      {#if g}<a class="btn sm" href="/policies/new?group={encodeURIComponent(g)}">+ policy in {g}</a>{/if}
    </div>
  {/if}
  {#if !closed[g]}
<div class="col" style="gap:12px">
  {#each ps as p (p.id)}
    {@const rule = parse(p.cedar)}
    <div class="card" style="opacity:{p.enabled ? 1 : 0.6}">
      <div class="row between" style="align-items:flex-start">
        <div class="grow">
          <div class="row"><a href="/policies/{p.id}"><b style="font-size:15px">{p.name}</b></a>
            {#if p.enabled}<span class="badge ok">enabled</span>{:else}<span class="badge plain">disabled</span>{/if}
            {#if rule}<span class="badge {rule.effect === 'permit' ? 'ok' : 'bad'} plain">{rule.effect}</span>{:else}<span class="badge plain" title="Written by hand; the builder cannot edit it">raw Cedar</span>{/if}
            {#if p.scope.length}<span class="chip" title={p.scope.map(nodeName).join(', ')}>only on {p.scope.map(nodeName).join(', ')}</span>{:else}<span class="chip">all nodes</span>{/if}
          </div>
          {#if p.description}<div class="muted" style="margin-top:4px">{p.description}</div>{/if}
          {#if rule}<div class="small" style="margin-top:6px">{describe(rule)}</div>{/if}
          <div class="faint small" style="margin-top:6px">updated <Time at={p.updated_at} /> by {p.updated_by || p.created_by || '?'}</div>
        </div>
        <div class="row" style="gap:6px">
          <a class="btn sm" href="/policies/{p.id}">Edit</a>
          <button class="btn sm" onclick={() => toggle(p)}>{p.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn sm danger" onclick={() => remove(p)}>Delete</button>
        </div>
      </div>
      <details style="margin-top:10px"><summary class="faint small" style="cursor:pointer">Cedar</summary><div class="cedar-preview" style="margin-top:8px">{@html highlight(p.cedar)}</div></details>
    </div>
  {/each}
</div>
  {/if}
{/each}
