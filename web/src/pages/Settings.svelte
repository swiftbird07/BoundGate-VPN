<script lang="ts">
  import { onMount } from 'svelte';
  import { admin, ApiError } from '../lib/api';
  import { auth } from '../lib/auth.svelte';
  import type { NetworkSettings, Renumbered } from '../lib/types';
  import { toast, fail } from '../lib/toast.svelte';

  let net = $state<NetworkSettings>({ pool: '', max_age_seconds: 0 });
  let snapshot = $state('');
  let showSnap = $state(false);
  onMount(async () => { try { net = await admin.network(); } catch (e) { fail(e); } });
  // nodes outside a new pool: the control plane lists them and waits for the word "renumber"
  let outside = $state<{ id: string; name: string; overlay_ip: string; status: string }[]>([]);
  let moved = $state<Renumbered[]>([]);
  async function save(renumber = false) {
    try {
      const r = await admin.putNetwork({ pool: net.pool, max_age_seconds: Number(net.max_age_seconds) || 0, ...(renumber ? { renumber: true } : {}) });
      net = { pool: r.pool, max_age_seconds: r.max_age_seconds };
      outside = []; moved = r.renumbered ?? [];
      toast(moved.length ? `Pool changed; ${moved.length} node(s) moved` : 'Network settings saved; snapshot bumped', 'ok');
    } catch (e) {
      const body = e instanceof ApiError ? (e.body as { outside?: typeof outside } | undefined) : undefined;
      if (e instanceof ApiError && e.status === 409 && body?.outside?.length) { outside = body.outside; moved = []; } else fail(e);
    }
  }
  async function loadSnap() { try { snapshot = JSON.stringify(await admin.snapshot(), null, 2); showSnap = true; } catch (e) { fail(e); } }
</script>

<div class="page-head"><div><h1>Settings</h1><div class="sub">Overlay network and control-plane facts.</div></div></div>
<div class="grid cols-2">
  <div class="card col" style="gap:12px">
    <h2>Overlay network</h2>
    <label class="field">Address pool <input class="mono" bind:value={net.pool} placeholder="10.21.0.0/16" /><span class="hint">Every node gets one stable address from this pool at confirmation.</span></label>
    <label class="field">Snapshot max age (seconds) <input type="number" min="0" bind:value={net.max_age_seconds} /><span class="hint">How long a node keeps enforcing with a snapshot it cannot refresh before it fails closed. 0 = registry default.</span></label>
    <div><button class="btn primary" onclick={() => save()}>Save</button></div>
    {#if outside.length}
      <div class="callout strong col" style="gap:8px">
        <strong>{outside.length} node{outside.length === 1 ? ' has' : 's have'} an address outside {net.pool}</strong>
        <span>They can move to the same host number in the new pool. The overlay address is part of what you sign, so every approved node among them drops out of the network until you have signed it again (Nodes, "Sign").</span>
        <ul class="mono" style="margin:0;padding-left:18px">{#each outside as o (o.id)}<li>{o.name} · {o.overlay_ip} · {o.status}</li>{/each}</ul>
        <div class="row" style="gap:8px"><button class="btn danger" onclick={() => save(true)}>Change the pool and renumber</button><button class="btn" onclick={() => (outside = [])}>Cancel</button></div>
      </div>
    {/if}
    {#if moved.length}
      <div class="callout col" style="gap:6px">
        <strong>Moved</strong>
        <ul class="mono" style="margin:0;padding-left:18px">{#each moved as m (m.id)}<li>{m.name}: {m.from} → {m.to}{m.needs_signature ? ' · sign again' : ''}</li>{/each}</ul>
        <a href="/nodes">Go to Nodes</a>
      </div>
    {/if}
  </div>
  <div class="card col" style="gap:12px">
    <h2>This session</h2>
    <dl class="kv">
      <dt>Signed in as</dt><dd>{auth.status?.name || auth.status?.subject}</dd>
      <dt>Via</dt><dd>{auth.status?.via}</dd>
      <dt>Level</dt><dd>{auth.status?.level}</dd>
      <dt>Passkey RP</dt><dd>{auth.status?.rp_id || '–'}</dd>
    </dl>
    <div><button class="btn" onclick={loadSnap}>Show global snapshot</button></div>
    {#if showSnap}<pre class="cedar-preview" style="max-height:480px; overflow:auto">{snapshot}</pre>{/if}
  </div>
</div>
