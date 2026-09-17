<script lang="ts">
  import { onMount } from 'svelte';
  import { admin, ApiError } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import type { Node, Grant, Role, Prefix } from '../lib/types';
  import Badge from '../lib/components/Badge.svelte';
  import Time from '../lib/components/Time.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import Dialog from '../lib/components/Dialog.svelte';
  import Copy from '../lib/components/Copy.svelte';
  import { toast, fail } from '../lib/toast.svelte';
  import { when } from '../lib/util';

  let nodes = $state<Node[]>([]);
  let filter = $state<'all' | 'pending' | 'confirmed' | 'approved' | 'revoked'>('all');
  let selected = $state<Node | null>(null);
  let signCmd = $state<{ cmd: string; expires: string } | null>(null);
  let confirm = $state<{ node: Node; edit: boolean } | null>(null);
  let g = $state<Required<Pick<Grant, 'name' | 'kind' | 'roles' | 'prefixes' | 'overlay_ip' | 'public_addr'>> & { checked: boolean; hardware: boolean }>({ name: '', kind: 'interactive', roles: [], prefixes: [], overlay_ip: '', public_addr: '', checked: false, hardware: false });
  let busy = $state(false);
  const allRoles: Role[] = ['endpoint', 'subnet-router', 'hub', 'exit-node'];

  async function load() {
    try {
      nodes = await admin.nodes();
      if (selected) selected = nodes.find((n) => n.id === selected!.id) ?? null;
      const want = route.query.get('id');
      if (want && !selected) selected = nodes.find((n) => n.id === want) ?? null;
    } catch (e) { fail(e); }
  }
  onMount(() => { void load(); const t = setInterval(load, 8000); return () => clearInterval(t); });
  const shown = $derived(nodes.filter((n) => filter === 'all' ? n.status !== 'revoked' : n.status === filter));
  const counts = $derived({ pending: nodes.filter((n) => n.status === 'pending').length, confirmed: nodes.filter((n) => n.status === 'confirmed').length, approved: nodes.filter((n) => n.status === 'approved').length, revoked: nodes.filter((n) => n.status === 'revoked').length });

  function select(n: Node | null) { selected = n; signCmd = null; navigate(n ? `/nodes?id=${n.id}` : '/nodes', true); }
  function openConfirm(n: Node, edit: boolean) {
    const roles = n.roles.length ? n.roles : n.requested_roles;
    const prefixes = n.prefixes.length ? n.prefixes : n.requested_prefixes;
    g = { name: n.name, kind: n.kind || 'interactive', roles: [...roles], prefixes: prefixes.map((p) => ({ ...p })), overlay_ip: n.overlay_ip || '', public_addr: n.public_addr || '', checked: edit, hardware: n.status === 'pending' ? !!n.hardware_claimed : n.hardware_bound };
    confirm = { node: n, edit };
  }
  function toggleRole(r: Role) { g.roles = g.roles.includes(r) ? g.roles.filter((x) => x !== r) : [...g.roles, r]; }
  async function submitConfirm() {
    if (!confirm) return;
    busy = true;
    try {
      const body: Grant = { fingerprint: confirm.node.fingerprint, name: g.name, kind: g.kind, roles: g.roles, prefixes: g.prefixes.filter((p) => p.prefix.trim()), overlay_ip: g.overlay_ip || undefined, public_addr: g.public_addr || undefined, hardware_bound: confirm.node.hardware_claimed ? g.hardware : undefined };
      const r = confirm.edit ? await admin.patchNode(confirm.node.id, body) : await admin.confirm(confirm.node.id, body);
      confirm = null;
      await load();
      selected = nodes.find((n) => n.id === r.id) ?? r;
      if (r.sign_command) { signCmd = { cmd: r.sign_command, expires: r.sign_expires_at || '' }; toast('Confirmed. Now sign the binding with an admin key.', 'ok'); }
      else toast('Saved', 'ok');
    } catch (e) { fail(e); } finally { busy = false; }
  }
  async function reissue(n: Node) {
    try { const r = await admin.confirm(n.id, {}); if (r.sign_command) signCmd = { cmd: r.sign_command, expires: r.sign_expires_at || '' }; } catch (e) { fail(e); }
  }
  async function reject(n: Node) {
    if (!window.confirm(`Reject ${n.name}? The node has to enroll again.`)) return;
    try { await admin.reject(n.id); toast('Rejected', 'ok'); select(null); await load(); } catch (e) { fail(e); }
  }
  async function revoke(n: Node) {
    if (!window.confirm(`Revoke ${n.name}? Its tunnels close within seconds and its key can never enroll again.`)) return;
    try { await admin.revoke(n.id); toast('Revoked', 'ok'); await load(); } catch (e) { fail(e); }
  }
</script>

<div class="page-head">
  <div><h1>Nodes</h1><div class="sub">Every device is approved twice: confirmed here after comparing its fingerprint, then signed with an admin key.</div></div>
  <div class="seg">
    {#each ['all', 'pending', 'confirmed', 'approved', 'revoked'] as f}
      <button class:active={filter === f} onclick={() => (filter = f as typeof filter)}>{f}{#if f !== 'all'} <span class="faint">{counts[f as keyof typeof counts]}</span>{/if}</button>
    {/each}
  </div>
</div>

<div class="card flush table-wrap">
  <table>
    <thead><tr><th>Node</th><th>Status</th><th>Kind</th><th>Roles</th><th>Overlay IP</th><th>Prefixes</th><th>Seen</th><th class="num">Tunnels</th></tr></thead>
    <tbody>
      {#each shown as n (n.id)}
        <tr class="clickable" class:selected={selected?.id === n.id} onclick={() => select(n)}>
          <td><b>{n.name}</b><div class="faint small">{n.hostname} · {n.platform} · {n.key_kind}{n.hardware_bound ? ' · hardware-bound' : n.hardware_claimed ? ' · reports a hardware key' : ''}</div></td>
          <td><Badge status={n.status} />{#if n.status === 'confirmed'}<div class="faint small">awaiting signature</div>{/if}</td>
          <td>{n.kind}</td>
          <td>{#each (n.roles.length ? n.roles : n.requested_roles) as r}<span class="chip">{r}</span> {/each}</td>
          <td class="mono">{n.overlay_ip || '–'}</td>
          <td>{#each (n.prefixes.length ? n.prefixes : n.requested_prefixes) as p}<span class="chip mono">{p.prefix} <span class="faint">{p.mode}</span></span> {/each}</td>
          <td><Time at={n.last_seen_at} /></td>
          <td class="num">{n.active_tunnels}</td>
        </tr>
      {:else}
        <tr><td colspan="8" class="empty">No nodes {filter === 'all' ? '' : filter}. Enroll one with <code>boundgatectl enroll</code>.</td></tr>
      {/each}
    </tbody>
  </table>
</div>

{#if selected}
  {@const n = selected}
  <Drawer title={n.name} onclose={() => select(null)}>
    <div class="col" style="gap:16px">
      <div class="row"><Badge status={n.status} />{#if n.signed}<span class="badge ok plain">signed by {n.signed_by}</span>{:else if n.status !== 'pending' && n.status !== 'revoked'}<span class="badge warn plain">not signed</span>{/if}<span class="chip">{n.kind}</span>{#if n.hardware_bound}<span class="chip">hardware-bound</span>{/if}</div>
      <div>
        <h3>Fingerprint</h3>
        <div class="cmd"><pre>{n.fingerprint}</pre><Copy text={n.fingerprint} /></div>
        <div class="hint" style="margin-top:6px">Compare with <code>boundgatectl identity</code> on the device before confirming.</div>
      </div>
      {#if signCmd}
        <div class="callout strong">
          <h3>Sign the binding</h3>
          <p class="small muted">Run this where the admin SSH key (YubiKey) is available. The token is single-use and expires {when(signCmd.expires)}.</p>
          <div class="cmd"><pre>{signCmd.cmd}</pre><Copy text={signCmd.cmd} /></div>
        </div>
      {/if}
      <div class="row">
        {#if n.status === 'pending'}
          <button class="btn primary" onclick={() => openConfirm(n, false)}>Confirm…</button>
          <button class="btn danger" onclick={() => reject(n)}>Reject</button>
        {:else if n.status === 'confirmed'}
          <button class="btn primary" onclick={() => reissue(n)}>Show sign command</button>
          <button class="btn" onclick={() => openConfirm(n, true)}>Edit grant…</button>
          <button class="btn danger" onclick={() => reject(n)}>Reject</button>
        {:else if n.status === 'approved'}
          <button class="btn" onclick={() => openConfirm(n, true)}>Edit grant…</button>
          <button class="btn danger" onclick={() => revoke(n)}>Revoke</button>
        {/if}
      </div>
      <dl class="kv">
        <dt>Node id</dt><dd class="mono">{n.id}</dd>
        <dt>Host</dt><dd>{n.hostname} · {n.platform}</dd>
        <dt>Key</dt><dd>{n.key_kind} v{n.key_version}{n.hardware_bound ? ' (hardware-bound, signed)' : n.hardware_claimed ? ' (reports a hardware key; not granted)' : ' (software key)'}</dd>
        <dt>SPKI</dt><dd class="mono small">{n.spki}</dd>
        <dt>Requested</dt><dd>{n.requested_roles.join(', ') || '–'} {#if n.requested_prefixes.length}· {n.requested_prefixes.map((p) => p.prefix).join(', ')}{/if} <span class="faint">from {n.request_ip} <Time at={n.requested_at} /></span></dd>
        <dt>Granted</dt><dd>{n.roles.join(', ') || '–'} {#if n.prefixes.length}· {n.prefixes.map((p) => `${p.prefix} (${p.mode})`).join(', ')}{/if}</dd>
        <dt>Overlay IP</dt><dd class="mono">{n.overlay_ip || '–'}</dd>
        {#if n.public_addr}<dt>Public address</dt><dd class="mono">{n.public_addr}</dd>{/if}
        {#if n.confirmed_at}<dt>Confirmed</dt><dd><Time at={n.confirmed_at} /> by {n.confirmed_by}</dd>{/if}
        {#if n.signed_at}<dt>Signed</dt><dd><Time at={n.signed_at} /> by {n.signed_by}</dd>{/if}
        {#if n.approved_at}<dt>Approved</dt><dd><Time at={n.approved_at} /> by {n.approved_by}</dd>{/if}
        {#if n.revoked_at}<dt>Revoked</dt><dd><Time at={n.revoked_at} /> by {n.revoked_by}</dd>{/if}
        <dt>Last seen</dt><dd><Time at={n.last_seen_at} /> · snapshot v{n.snapshot_version} · {n.active_tunnels} tunnels</dd>
      </dl>
      <div class="row"><a class="btn sm" href="/logs?tab=flows&node={n.id}">Flows</a><a class="btn sm" href="/logs?tab=tunnels&node={n.id}">Tunnels</a><a class="btn sm" href="/logs?tab=audit&node={n.id}">Audit</a></div>
    </div>
  </Drawer>
{/if}

{#if confirm}
  <Dialog title={confirm.edit ? `Edit grant for ${confirm.node.name}` : `Confirm ${confirm.node.name}`} onclose={() => (confirm = null)}>
    <div class="col" style="gap:14px">
      {#if !confirm.edit}
        <div class="cmd"><pre>{confirm.node.fingerprint}</pre></div>
        <label class="check"><input type="checkbox" bind:checked={g.checked} /> I compared this fingerprint with the one the device shows</label>
      {:else}
        <p class="hint">Changing a signed field (kind, roles, prefixes, overlay IP, hardware-bound) demotes an approved node to <i>confirmed</i> until an admin signs the new binding.</p>
      {/if}
      <div class="grid cols-2">
        <label class="field">Name <input bind:value={g.name} /></label>
        <label class="field">Kind <select bind:value={g.kind}><option value="interactive">interactive (a user logs in)</option><option value="workload">workload (no user session)</option></select></label>
      </div>
      {#if confirm.node.hardware_claimed}
        <label class="check"><input type="checkbox" bind:checked={g.hardware} /> Hardware-bound: this machine keeps its key in a TPM ({confirm.node.key_kind})</label>
        <p class="hint">The node says so; nothing proves it remotely. Tick it if you know the machine. It becomes part of the signed binding, and policies can require it (<code>principal.hardware_bound</code>).</p>
      {/if}
      <div class="field"><span>Roles</span><div class="row">{#each allRoles as r}<label class="check"><input type="checkbox" checked={g.roles.includes(r)} onchange={() => toggleRole(r)} /> {r}</label>{/each}</div></div>
      <div class="grid cols-2">
        <label class="field">Overlay IP <input placeholder="next free address" bind:value={g.overlay_ip} /></label>
        <label class="field">Public address (hubs) <input placeholder="hub.example:443" bind:value={g.public_addr} /></label>
      </div>
      <div class="field"><span>Announced prefixes</span>
        <div class="col" style="gap:6px">
          {#each g.prefixes as p, i}
            <div class="row"><input class="grow mono" placeholder="192.168.178.0/24" bind:value={p.prefix} /><select bind:value={p.mode}><option value="routed">routed</option><option value="snat">snat</option></select><button class="btn sm ghost" onclick={() => g.prefixes.splice(i, 1)}>✕</button></div>
          {/each}
          <div><button class="btn sm" onclick={() => g.prefixes.push({ prefix: '', mode: 'routed' })}>+ prefix</button></div>
        </div>
      </div>
    </div>
    {#snippet footer()}
      <button class="btn" onclick={() => (confirm = null)}>Cancel</button>
      <button class="btn primary" disabled={busy || !g.checked || g.roles.length === 0} onclick={submitConfirm}>{confirm?.edit ? 'Save' : 'Confirm'}</button>
    {/snippet}
  </Dialog>
{/if}
