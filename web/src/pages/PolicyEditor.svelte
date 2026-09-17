<script lang="ts">
  import { onMount } from 'svelte';
  import { admin, ApiError } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import type { Policy, Node, Session, NetworkSettings } from '../lib/types';
  import { parse, generate, emptyRule, describe, highlight, type Rule } from '../lib/cedar';
  import Builder from './policy/Builder.svelte';
  import SanityCheck from './policy/SanityCheck.svelte';
  import { toast, fail } from '../lib/toast.svelte';

  const id = $derived(route.path.split('/')[2] || 'new');
  const isNew = $derived(id === 'new');
  let loaded = $state(false);
  let name = $state('');
  let description = $state('');
  let enabled = $state(true);
  let scope = $state<string[]>([]);
  let mode = $state<'builder' | 'cedar'>('builder');
  let rule = $state<Rule>(emptyRule());
  let cedar = $state('');            // authoritative in cedar mode
  let nodes = $state<Node[]>([]);
  let sessions = $state<Session[]>([]);
  let network = $state<NetworkSettings | null>(null);
  let validation = $state<{ ok: boolean; error?: string } | null>(null);
  let busy = $state(false);
  let original = $state<Policy | null>(null);

  const effectiveCedar = $derived(mode === 'builder' ? generate(rule) : cedar);
  const dirty = $derived(!original ? true : original.name !== name || (original.description || '') !== description || original.enabled !== enabled || original.scope.join() !== scope.join() || original.cedar.trim() !== effectiveCedar.trim());
  const groups = $derived([...new Set(sessions.flatMap((s) => s.groups))].sort());

  onMount(async () => {
    try {
      [nodes, sessions, network] = await Promise.all([admin.nodes(), admin.sessions(true), admin.network().catch(() => null)]);
      if (!isNew) {
        const ps = await admin.policies();
        const p = ps.find((x) => x.id === id);
        if (!p) { toast('Policy not found', 'bad'); navigate('/policies'); return; }
        original = p;
        name = p.name; description = p.description || ''; enabled = p.enabled; scope = [...p.scope]; cedar = p.cedar;
        const r = parse(p.cedar);
        if (r) { rule = r; mode = 'builder'; } else { mode = 'cedar'; }
      } else {
        const tpl = route.query.get('template');
        if (tpl === 'allow-all') rule = { ...emptyRule(), effect: 'permit' };
      }
    } catch (e) { fail(e); }
    loaded = true;
  });

  // live validation of the Cedar text (debounced)
  let vt: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const text = effectiveCedar;
    clearTimeout(vt);
    vt = setTimeout(async () => { try { validation = await admin.validate(text); } catch (e: any) { validation = { ok: false, error: e.message }; } }, 250);
  });

  function switchMode(m: typeof mode) {
    if (m === mode) return;
    if (m === 'cedar') { cedar = generate(rule); mode = 'cedar'; return; }
    const r = parse(cedar);
    if (!r) { toast('This Cedar uses constructs the builder cannot represent; keep editing it as text.', 'bad'); return; }
    rule = r; mode = 'builder';
  }
  async function save() {
    busy = true;
    try {
      const body = { name: name.trim(), description: description.trim(), cedar: effectiveCedar, enabled, scope };
      if (!body.name) { toast('Give the policy a name', 'bad'); return; }
      const p = isNew ? await admin.createPolicy(body) : await admin.putPolicy(id, body);
      original = p; cedar = p.cedar;
      toast(isNew ? 'Policy created; nodes pick it up within seconds' : 'Policy saved', 'ok');
      if (isNew) navigate('/policies/' + p.id, true);
    } catch (e) { fail(e); } finally { busy = false; }
  }
  async function remove() {
    if (!original || !window.confirm(`Delete policy “${original.name}”?`)) return;
    try { await admin.deletePolicy(original.id); toast('Deleted', 'ok'); navigate('/policies'); } catch (e) { fail(e); }
  }
  function toggleScope(nid: string) { scope = scope.includes(nid) ? scope.filter((x) => x !== nid) : [...scope, nid]; }
</script>

<div class="page-head">
  <div><h1>{isNew ? 'New policy' : name || 'Policy'}</h1><div class="sub"><a href="/policies">← all policies</a>{#if original}&nbsp;· updated by {original.updated_by || original.created_by} {/if}</div></div>
  <div class="row">
    {#if !isNew}<button class="btn danger" onclick={remove}>Delete</button>{/if}
    <button class="btn primary" disabled={busy || !dirty || validation?.ok === false} onclick={save}>{isNew ? 'Create policy' : 'Save changes'}</button>
  </div>
</div>

{#if !loaded}
  <div class="row"><span class="spinner"></span></div>
{:else}
<div class="grid" style="grid-template-columns: minmax(0, 1.4fr) minmax(320px, 1fr); align-items:start">
  <div class="col" style="gap:14px">
    <div class="card col" style="gap:12px">
      <div class="grid cols-2">
        <label class="field">Name <input placeholder="lan-for-vpn-users" bind:value={name} /></label>
        <label class="field">Description <input placeholder="what this policy is for" bind:value={description} /></label>
      </div>
      <div class="row between">
        <label class="check"><input type="checkbox" bind:checked={enabled} /> enabled</label>
        <details><summary class="small muted" style="cursor:pointer">Scope: {scope.length ? `${scope.length} node(s)` : 'all nodes'}</summary>
          <div class="row" style="margin-top:8px">
            {#each nodes.filter((n) => n.status === 'approved' || n.status === 'confirmed') as n}
              <label class="check small"><input type="checkbox" checked={scope.includes(n.id)} onchange={() => toggleScope(n.id)} /> {n.name} <span class="faint">{n.roles.join('/')}</span></label>
            {/each}
          </div>
          <div class="hint" style="margin-top:6px">Scoped policies are only sent to (and enforced on) the selected nodes. Leave empty for every node.</div>
        </details>
      </div>
    </div>

    <div class="card col" style="gap:12px">
      <div class="row between">
        <h2>Rule</h2>
        <div class="seg"><button class:active={mode === 'builder'} onclick={() => switchMode('builder')}>Builder</button><button class:active={mode === 'cedar'} onclick={() => switchMode('cedar')}>Cedar</button></div>
      </div>
      {#if mode === 'builder'}
        <Builder bind:rule {nodes} {groups} pool={network?.pool} />
        <div>
          <h3 style="margin-bottom:6px">Reads as</h3>
          <div class="muted">{describe(rule)}</div>
        </div>
        <div>
          <h3 style="margin-bottom:6px">Generated Cedar</h3>
          <div class="cedar-preview">{@html highlight(effectiveCedar)}</div>
        </div>
      {:else}
        <textarea class="code" rows="14" bind:value={cedar} spellcheck="false"></textarea>
        <div class="hint">Entities: <code>BoundGate::Node</code>, <code>User</code>, <code>Group</code>, <code>Role</code>, <code>Host</code> (resource; <code>ip</code>, <code>port</code>, <code>protocol</code>, <code>sni</code>, <code>dns_name</code>), <code>Network</code>. See docs/ACL.md.</div>
      {/if}
      {#if validation}
        {#if validation.ok}<div class="ok small">✓ Cedar parses</div>{:else}<div class="error small">✕ {validation.error}</div>{/if}
      {/if}
    </div>
  </div>

  <SanityCheck {nodes} draft={{ id: isNew ? 'draft' : id, name: name || '(draft)', cedar: effectiveCedar }} valid={validation?.ok !== false} {dirty} />
</div>
{/if}
