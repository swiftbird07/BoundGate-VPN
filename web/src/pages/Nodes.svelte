<script lang="ts">
  import { onMount } from 'svelte';
  import { admin, ApiError } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import type { Node, Grant, Role, Prefix, TagOffer } from '../lib/types';
  import Badge from '../lib/components/Badge.svelte';
  import Time from '../lib/components/Time.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import Dialog from '../lib/components/Dialog.svelte';
  import Copy from '../lib/components/Copy.svelte';
  import SignCommand from '../lib/components/SignCommand.svelte';
  import { toast, fail } from '../lib/toast.svelte';
  import { when } from '../lib/util';

  let nodes = $state<Node[]>([]);
  let filter = $state<'all' | 'pending' | 'confirmed' | 'approved' | 'revoked'>('all');
  let selected = $state<Node | null>(null);
  let signCmd = $state<{ cmd: string; expires: string; revocation?: boolean } | null>(null);
  let confirm = $state<{ node: Node; edit: boolean } | null>(null);
  let g = $state<Required<Pick<Grant, 'name' | 'kind' | 'roles' | 'prefixes' | 'overlay_ip' | 'public_addr' | 'tags'>> & { checked: boolean; hardware: boolean }>({ name: '', kind: 'interactive', roles: [], prefixes: [], overlay_ip: '', public_addr: '', tags: [], checked: false, hardware: false });
  let tagFilter = $state('');
  let tagInput = $state('');
  let offer = $state<TagOffer>({ defaults: [], used: [] });
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
  // what a device shows at its first contact; its user compares it with this
  let controlPin = $state('');
  onMount(() => { admin.identity().then((i) => (controlPin = i.control_pin)).catch(() => {}); });
  onMount(() => { void load(); const t = setInterval(load, 8000); return () => clearInterval(t); });
  const shown = $derived(nodes.filter((n) => (filter === 'all' ? n.status !== 'revoked' : n.status === filter) && (!tagFilter || (n.tags ?? []).includes(tagFilter))));
  const tagsInUse = $derived([...new Set(nodes.filter((n) => n.status !== 'revoked').flatMap((n) => n.tags ?? []))].sort());
  // the built-in tags first, then what other nodes carry; never what this node has already
  const suggestions = $derived([...offer.defaults, ...offer.used.filter((t) => !offer.defaults.includes(t))].filter((t) => !g.tags.includes(t)));
  // the server's rule (internal/control/db: CleanTags), so a typo shows here and not as a 400
  const tagOK = (t: string) => /^[a-z0-9][a-z0-9._-]{0,31}$/.test(t);
  // also takes a pasted list ("laptop, office"); what does not fit stays in the input
  function addTag(raw: string) {
    const left: string[] = [];
    for (const t of raw.toLowerCase().split(/[\s,]+/).filter(Boolean)) {
      if (g.tags.includes(t)) continue;
      if (!tagOK(t)) { left.push(t); toast(`"${t}" is not a tag: up to 32 of a-z, 0-9, ".", "_" and "-", starting with a letter or digit`, 'bad'); }
      else if (g.tags.length >= 16) { left.push(t); toast('At most 16 tags per node', 'bad'); }
      else g.tags = [...g.tags, t].sort();
    }
    tagInput = left.join(' ');
  }
  function tagKey(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',' || e.key === ' ') { e.preventDefault(); addTag(tagInput); }
    else if (e.key === 'Backspace' && !tagInput && g.tags.length) g.tags = g.tags.slice(0, -1);
  }
  const counts = $derived({ pending: nodes.filter((n) => n.status === 'pending').length, confirmed: nodes.filter((n) => n.status === 'confirmed').length, approved: nodes.filter((n) => n.status === 'approved').length, revoked: nodes.filter((n) => n.status === 'revoked').length });

  function select(n: Node | null) { selected = n; signCmd = null; navigate(n ? `/nodes?id=${n.id}` : '/nodes', true); }
  function openConfirm(n: Node, edit: boolean) {
    const roles = n.roles.length ? n.roles : n.requested_roles;
    const prefixes = n.prefixes.length ? n.prefixes : n.requested_prefixes;
    // a hub serves others and has no user: a new one starts as a workload
    const kind = n.status === 'pending' && roles.includes('hub') ? 'workload' : n.kind || 'interactive';
    g = { name: n.name, kind, roles: [...roles], prefixes: prefixes.map((p) => ({ ...p })), overlay_ip: n.overlay_ip || '', public_addr: n.public_addr || '', tags: [...(n.tags ?? [])], checked: edit, hardware: n.status === 'pending' ? !!n.hardware_claimed : n.hardware_bound };
    tagInput = '';
    admin.tags().then((o) => (offer = o)).catch(() => {});
    confirm = { node: n, edit };
  }
  function toggleRole(r: Role) {
    const on = !g.roles.includes(r);
    g.roles = on ? [...g.roles, r] : g.roles.filter((x) => x !== r);
    if (on && r === 'hub') g.kind = 'workload';
  }
  async function submitConfirm() {
    if (!confirm) return;
    if (tagInput.trim()) { addTag(tagInput); if (tagInput) return; }
    busy = true;
    try {
      // public_addr is always sent: empty means none (every peer routes it around the overlay)
      const body: Grant = { fingerprint: confirm.node.fingerprint, name: g.name, kind: g.kind, roles: g.roles, prefixes: g.prefixes.filter((p) => p.prefix.trim()), overlay_ip: g.overlay_ip || undefined, public_addr: g.public_addr.trim(), tags: g.tags, hardware_bound: confirm.node.hardware_claimed ? g.hardware : undefined };
      const r = confirm.edit ? await admin.patchNode(confirm.node.id, body) : await admin.confirm(confirm.node.id, body);
      confirm = null;
      await load();
      selected = nodes.find((n) => n.id === r.id) ?? r;
      if (r.sign_command) { signCmd = { cmd: r.sign_command, expires: r.sign_expires_at || '' }; toast('Confirmed. Now sign the binding with an admin key.', 'ok'); }
      else toast('Saved', 'ok');
    } catch (e) { fail(e); } finally { busy = false; }
  }
  async function reissue(n: Node) {
    // the grant as it stands, hardware_bound included: a new token must not change it
    try { const r = await admin.confirm(n.id, { hardware_bound: n.hardware_bound }); if (r.sign_command) signCmd = { cmd: r.sign_command, expires: r.sign_expires_at || '' }; } catch (e) { fail(e); }
  }
  async function reject(n: Node) {
    if (!window.confirm(`Reject ${n.name}? The node has to enroll again.`)) return;
    try { await admin.reject(n.id); toast('Rejected', 'ok'); select(null); await load(); } catch (e) { fail(e); }
  }
  async function revoke(n: Node) {
    if (!window.confirm(`Revoke ${n.name}? Its tunnels close within seconds and its key can never enroll again.`)) return;
    try {
      await admin.revoke(n.id);
      toast('Revoked. Now sign the revocation with an admin key.', 'ok');
      await load();
      await signRevocation(n);
    } catch (e) { fail(e); }
  }
  // The revocation holds against this control plane only once an admin
  // signed it: then every node refuses the old binding for good (R119).
  async function signRevocation(n: Node) {
    try {
      const r = await admin.revocationToken(n.id);
      selected = nodes.find((x) => x.id === n.id) ?? selected;
      if (r.sign_command) signCmd = { cmd: r.sign_command, expires: r.sign_expires_at || '', revocation: true };
    } catch (e) { fail(e); }
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
{#if tagsInUse.length}
  <div class="tagbar small">
    <span class="muted">Tags</span>
    {#each tagsInUse as t}<button class="chip tag" class:on={tagFilter === t} onclick={() => (tagFilter = tagFilter === t ? '' : t)}>{t}</button>{/each}
    {#if tagFilter}<button class="btn sm ghost" onclick={() => (tagFilter = '')}>clear</button>{/if}
  </div>
{/if}
{#if controlPin}
  <div class="pinline small">
    <span class="muted">Control plane fingerprint</span>
    <span class="mono">{controlPin}</span><Copy text={controlPin} />
    <span class="faint">A device shows this at its first contact (<code>boundgatectl enroll</code>, the app) and pins it. Give it to the device's user; if theirs differs, they must not continue.</span>
  </div>
{/if}

<div class="card flush table-wrap">
  <table>
    <thead><tr><th>Node</th><th>Status</th><th>Kind</th><th>Roles</th><th>Overlay IP</th><th>Prefixes</th><th>Seen</th><th class="num">Tunnels</th></tr></thead>
    <tbody>
      {#each shown as n (n.id)}
        <tr class="clickable" class:selected={selected?.id === n.id} onclick={() => select(n)}>
          <td><b>{n.name}</b><div class="faint small">{n.hostname} · {n.platform} · {n.key_kind}{n.hardware_bound ? ' · hardware-bound' : n.hardware_claimed ? ' · reports a hardware key' : ''}</div>{#if n.tags?.length}<div class="tags">{#each n.tags as t}<span class="chip tag">{t}</span>{/each}</div>{/if}</td>
          <td><Badge status={n.status} />{#if n.status === 'confirmed'}<div class="faint small">awaiting signature</div>{/if}</td>
          <td>{n.kind}</td>
          <td>{#each (n.roles.length ? n.roles : n.requested_roles) as r}<span class="chip">{r}</span> {/each}</td>
          <td class="mono">{n.overlay_ip || '–'}</td>
          <td>{#each (n.prefixes.length ? n.prefixes : n.requested_prefixes) as p}<span class="chip mono">{p.prefix} <span class="faint">{p.mode}</span></span> {/each}</td>
          <td><Time at={n.last_seen_at} /></td>
          <td class="num">{n.active_tunnels}</td>
        </tr>
      {:else}
        <tr><td colspan="8" class="empty">{#if tagFilter}No {filter === 'all' ? '' : filter} nodes tagged <span class="chip tag">{tagFilter}</span>.{:else}No nodes {filter === 'all' ? '' : filter}. Enroll one with <code>boundgatectl enroll</code>.{/if}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

{#if selected}
  {@const n = selected}
  <Drawer title={n.name} onclose={() => select(null)}>
    <div class="col" style="gap:16px">
      <div class="row"><Badge status={n.status} />{#if n.status === 'revoked'}{#if n.revocation_signed}<span class="badge ok plain">revocation signed</span>{:else}<span class="badge warn plain">revocation not signed</span>{/if}{:else if n.signed}<span class="badge ok plain">signed by {n.signed_by}</span>{:else if n.status !== 'pending'}<span class="badge warn plain">not signed</span>{/if}<span class="chip">{n.kind}</span>{#if n.hardware_bound}<span class="chip">hardware-bound</span>{/if}</div>
      <div>
        <h3>Fingerprint</h3>
        <div class="cmd"><pre>{n.fingerprint}</pre><Copy text={n.fingerprint} /></div>
        <div class="hint" style="margin-top:6px">Compare with <code>boundgatectl identity</code> on the device before confirming.</div>
      </div>
      {#if signCmd}
        <div class="callout strong">
          {#if signCmd.revocation}
            <h3>Sign the revocation</h3>
            <p class="small muted">The node is revoked already. Signing makes it stick: every node then refuses its old binding for good, even if this control plane were to serve it again. Run this where the admin SSH key (YubiKey) is available; the token is single-use and expires {when(signCmd.expires)}.</p>
          {:else}
            <h3>Sign the binding</h3>
            <p class="small muted">Run this where the admin SSH key (YubiKey) is available. The token is single-use and expires {when(signCmd.expires)}.</p>
          {/if}
          <SignCommand command={signCmd.cmd} />
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
        {:else if n.status === 'revoked' && !n.revocation_signed}
          <button class="btn primary" onclick={() => signRevocation(n)}>Sign revocation</button>
        {/if}
      </div>
      <dl class="kv">
        <dt>Node id</dt><dd class="mono">{n.id}</dd>
        <dt>Host</dt><dd>{n.hostname} · {n.platform}</dd>
        <dt>Key</dt><dd>{n.key_kind} v{n.key_version}{n.hardware_bound ? ' (hardware-bound, signed)' : n.hardware_claimed ? ' (reports a hardware key; not granted)' : ' (software key)'}</dd>
        <dt>SPKI</dt><dd class="mono small">{n.spki}</dd>
        <dt>Requested</dt><dd>{n.requested_roles.join(', ') || '–'} {#if n.requested_prefixes.length}· {n.requested_prefixes.map((p) => p.prefix).join(', ')}{/if} <span class="faint">from {n.request_ip} <Time at={n.requested_at} /></span></dd>
        <dt>Granted</dt><dd>{n.roles.join(', ') || '–'} {#if n.prefixes.length}· {n.prefixes.map((p) => `${p.prefix} (${p.mode})`).join(', ')}{/if}</dd>
        <dt>Tags</dt><dd>{#each n.tags ?? [] as t}<span class="chip tag">{t}</span> {:else}–{/each}</dd>
        <dt>Overlay IP</dt><dd class="mono">{n.overlay_ip || '–'}</dd>
        {#if n.public_addr}<dt>Public address</dt><dd class="mono">{n.public_addr}</dd>{/if}
        {#if n.requested_public_addr && n.requested_public_addr !== n.public_addr}<dt>Asked for</dt><dd><span class="mono">{n.requested_public_addr}</span> <span class="faint">as public address; not in effect unless you set it</span></dd>{/if}
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
        <p class="hint">Changing a signed field (kind, roles, tags, prefixes, overlay IP, hardware-bound) demotes an approved node to <i>confirmed</i> until an admin signs the new binding.</p>
      {/if}
      <div class="grid cols-2">
        <label class="field">Name <input bind:value={g.name} /></label>
        <label class="field">Kind <select bind:value={g.kind}><option value="interactive">interactive (a user logs in)</option><option value="workload">workload (no user session)</option></select></label>
      </div>
      {#if g.kind === 'interactive' && g.roles.includes('hub')}
        <p class="callout small"><b>A hub with a user?</b> An interactive node needs a signed-in user before other nodes and its own tunnels let it through. A hub has none: confirm it as a <i>workload</i>.</p>
      {/if}
      {#if confirm.node.hardware_claimed}
        <label class="check"><input type="checkbox" bind:checked={g.hardware} /> Hardware-bound: this machine keeps its key in hardware, a TPM or a Mac's Secure Enclave ({confirm.node.key_kind})</label>
        <p class="hint">The node says so; nothing proves it remotely. Tick it if you know the machine. It becomes part of the signed binding, and policies can require it (<code>principal.hardware_bound</code>).</p>
      {/if}
      <div class="field"><span>Roles</span><div class="row">{#each allRoles as r}<label class="check"><input type="checkbox" checked={g.roles.includes(r)} onchange={() => toggleRole(r)} /> {r}</label>{/each}</div></div>
      <div class="field"><span>Tags</span>
        <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
        <div class="tagbox" onclick={(e) => (e.currentTarget.querySelector('input') as HTMLInputElement).focus()}>
          {#each g.tags as t}<span class="chip tag on">{t}<button aria-label="remove {t}" onclick={(e) => { e.stopPropagation(); g.tags = g.tags.filter((x) => x !== t); }}>✕</button></span>{/each}
          <input placeholder={g.tags.length ? '' : 'pick below or type your own'} bind:value={tagInput} onkeydown={tagKey} onblur={() => addTag(tagInput)} />
        </div>
        {#if suggestions.length}<div class="suggest">{#each suggestions as t}<button class="chip tag" onclick={() => addTag(t)}>+ {t}</button>{/each}</div>{/if}
        <span class="hint">Policies select nodes by tag (<code>principal in BoundGate::Tag::"laptop"</code>), so tags are part of the binding your admin key signs: the control plane cannot hand one out by itself.</span>
      </div>
      <div class="grid cols-2">
        <label class="field">Overlay IP <input placeholder="next free address" bind:value={g.overlay_ip} /></label>
        <label class="field">Public address (hubs) <input placeholder="hub.example:443" bind:value={g.public_addr} /></label>
      </div>
      {#if confirm.node.requested_public_addr && confirm.node.requested_public_addr !== g.public_addr}
        <p class="hint">The node asks for <span class="mono">{confirm.node.requested_public_addr}</span> as its public address. <button class="btn sm" onclick={() => (g.public_addr = confirm!.node.requested_public_addr ?? '')}>Use it</button><br />Every peer sends traffic for this address outside the tunnel, so set it only for a node that really listens there. Empty means none.</p>
      {/if}
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

<style>
  .pinline { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; margin: -0.25rem 0 1rem; }
  .tagbar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; margin: -0.25rem 0 1rem; }
  .tags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
  .chip.tag { border-radius: 999px; font-weight: 500; }
  button.chip.tag { cursor: pointer; font-family: inherit; }
  button.chip.tag:hover { border-color: var(--accent); color: var(--text); }
  .chip.tag.on { background: color-mix(in srgb, var(--accent) 16%, transparent); border-color: color-mix(in srgb, var(--accent) 55%, transparent); color: var(--text); }
  .chip.tag.on button { all: unset; cursor: pointer; margin-left: 6px; font-size: 10px; opacity: 0.65; }
  .chip.tag.on button:hover { opacity: 1; }
  .tagbox { display: flex; flex-wrap: wrap; align-items: center; gap: 5px; padding: 5px 8px; min-height: 36px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); cursor: text; }
  .tagbox:focus-within { border-color: var(--accent); }
  .tagbox input { all: unset; flex: 1; min-width: 9rem; font-size: 13px; padding: 2px 0; }
  .suggest { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
</style>
