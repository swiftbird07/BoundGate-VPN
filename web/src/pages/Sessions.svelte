<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { Session } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import Badge from '../lib/components/Badge.svelte';
  import { toast, fail } from '../lib/toast.svelte';

  let sessions = $state<Session[]>([]);
  let all = $state(false);
  async function load() { try { sessions = await admin.sessions(all); } catch (e) { fail(e); } }
  onMount(() => { void load(); const t = setInterval(load, 8000); return () => clearInterval(t); });
  $effect(() => { all; void load(); });
  async function revoke(s: Session) {
    if (!window.confirm(`End the session of ${s.username || s.subject} on ${s.node_name}? Hubs close its tunnels immediately.`)) return;
    try { await admin.revokeSession(s.id); toast('Session ended', 'ok'); await load(); } catch (e) { fail(e); }
  }
</script>

<div class="page-head">
  <div><h1>User sessions</h1><div class="sub">One session per interactive node, granted by the identity provider, enforced by hubs.</div></div>
  <label class="check"><input type="checkbox" bind:checked={all} /> include ended sessions</label>
</div>
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
          <td>{#if !s.ended_at}<button class="btn sm danger" onclick={() => revoke(s)}>End</button>{/if}</td>
        </tr>
      {:else}
        <tr><td colspan="7" class="empty">No {all ? '' : 'active '}sessions.</td></tr>
      {/each}
    </tbody>
  </table>
</div>
