<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { Session } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import Badge from '../lib/components/Badge.svelte';
  import { toast, fail } from '../lib/toast.svelte';
  import { poll, type PollState } from '../lib/poll';
  import Updated from '../lib/components/Updated.svelte';

  let sessions = $state<Session[]>([]);
  let all = $state(false);
  let loaded = $state(false);
  let ending = $state('');
  let ps = $state<PollState>({ busy: false, error: '', failures: 0 });
  async function load() { sessions = await admin.sessions(all); loaded = true; }
  const poller = poll({ run: load, every: 8000, onState: (s) => (ps = s) });
  onMount(() => poller.start());
  $effect(() => { all; void poller.refresh(); });
  async function revoke(s: Session) {
    if (!window.confirm(`End the session of ${s.username || s.subject} on ${s.node_name}? Hubs close its tunnels immediately.`)) return;
    ending = s.id;
    try { await admin.revokeSession(s.id); toast('Session ended', 'ok'); await poller.refresh(); } catch (e) { fail(e); }
    ending = '';
  }
</script>

<div class="page-head">
  <div><h1>User sessions</h1><div class="sub">One session per node, granted by the identity provider. What it opens is up to the policies.</div></div>
  <div class="row" style="gap:12px; align-items:center">
    <label class="check"><input type="checkbox" bind:checked={all} /> include ended sessions</label>
    <Updated info={ps} refresh={poller.refresh} />
  </div>
</div>
{#if ps.error}<p class="error">{ps.error}</p>{/if}
<div class="card flush table-wrap">
  <table>
    <thead><tr><th>User</th><th>Node</th><th>Groups</th><th>Status</th><th>Issued</th><th>Expires</th><th></th></tr></thead>
    <tbody>
      {#each sessions as s (s.id)}
        <tr>
          <td><b>{s.username || s.subject}</b><div class="faint small">{s.email} · from {s.login_ip}</div></td>
          <td>{s.node_name || s.node_id}</td>
          <td>{#each s.groups as g}<span class="chip">{g}</span> {/each}</td>
          <td>{#if s.ended_at}<Badge status="ended" label={s.end_reason || 'ended'} /><div class="faint small">by {s.ended_by} <Time at={s.ended_at} /></div>{:else}<Badge status="active" />{/if}</td>
          <td><Time at={s.issued_at} /></td>
          <td><Time at={s.expires_at} /></td>
          <td>{#if !s.ended_at}<button class="btn sm danger" onclick={() => revoke(s)} disabled={ending === s.id}>{ending === s.id ? 'Ending…' : 'End'}</button>{/if}</td>
        </tr>
      {:else}
        <tr><td colspan="7" class="empty">{#if !loaded}<span class="spinner"></span> Asking the control plane…{:else}No {all ? '' : 'active '}sessions.{/if}</td></tr>
      {/each}
    </tbody>
  </table>
</div>
