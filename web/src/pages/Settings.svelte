<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import { auth } from '../lib/auth.svelte';
  import type { NetworkSettings } from '../lib/types';
  import { toast, fail } from '../lib/toast.svelte';

  let net = $state<NetworkSettings>({ pool: '', max_age_seconds: 0 });
  let snapshot = $state('');
  let showSnap = $state(false);
  onMount(async () => { try { net = await admin.network(); } catch (e) { fail(e); } });
  async function save() { try { net = await admin.putNetwork({ pool: net.pool, max_age_seconds: Number(net.max_age_seconds) || 0 }); toast('Network settings saved; snapshot bumped', 'ok'); } catch (e) { fail(e); } }
  async function loadSnap() { try { snapshot = JSON.stringify(await admin.snapshot(), null, 2); showSnap = true; } catch (e) { fail(e); } }
</script>

<div class="page-head"><div><h1>Settings</h1><div class="sub">Overlay network and control-plane facts.</div></div></div>
<div class="grid cols-2">
  <div class="card col" style="gap:12px">
    <h2>Overlay network</h2>
    <label class="field">Address pool <input class="mono" bind:value={net.pool} placeholder="10.21.0.0/16" /><span class="hint">Every node gets one stable address from this pool at confirmation.</span></label>
    <label class="field">Snapshot max age (seconds) <input type="number" min="0" bind:value={net.max_age_seconds} /><span class="hint">How long a node keeps enforcing with a snapshot it cannot refresh before it fails closed. 0 = registry default.</span></label>
    <div><button class="btn primary" onclick={save}>Save</button></div>
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
