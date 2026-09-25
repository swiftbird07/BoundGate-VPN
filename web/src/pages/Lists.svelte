<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { AclList, ListKind } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import { toast, fail } from '../lib/toast.svelte';

  let lists = $state<AclList[]>([]);
  let loaded = $state(false);
  // the editor: a new list, or a copy of an existing one
  type Draft = { id?: string; name: string; kind: ListKind; description: string; text: string;
    source_url: string; source_minutes: number; source_header: string; source_secret: string; secret_set: boolean; stored_url: string };
  let editing = $state<Draft | null>(null);
  let busy = $state(false);
  let fetching = $state<string | null>(null);
  let importInto = $state<AclList | null>(null);
  let fileInput: HTMLInputElement | undefined = $state();
  const kindLabel: Record<ListKind, string> = { dynamic: 'Dynamic access list', ip: 'Addresses', dns: 'DNS names', sni: 'TLS server names' };
  const kindHelp: Record<ListKind, string> = {
    dynamic: 'Names and addresses together, one per line: *.github.com, myip.wtf, 10.60.0.10, 10.60.0.64/26, 192.168.178.20-192.168.178.29, 10.60.0.11:443, 10.60.0.12:8000-8100 ([2001:db8::1]:443 for IPv6). A name counts however the node sees it: it answers the DNS query, remembers for that device which addresses the answer named and lets the connection to them through under that name — TLS or not — and a TLS server name still matches on its own. The node believes only the resolvers it offers (hub option dns, or dns_learn_from); see docs/ACL.md.',
    ip: 'One address or CIDR prefix per line: 10.60.0.11, 192.168.178.0/24.',
    dns: 'One name per line. *.example.com matches every name under example.com (not example.com itself). Matched against the question of DNS queries.',
    sni: 'One name per line, * at the start matches any number of labels. Matched against the TLS ClientHello; a permit by such a list decides after the handshake (docs/ACL.md).',
  };

  async function load() { try { lists = await admin.lists(); } catch (e) { fail(e); } loaded = true; }
  onMount(() => { void load(); });

  function start(l?: AclList) {
    editing = l
      ? { id: l.id, name: l.name, kind: l.kind, description: l.description || '', text: l.entries.join('\n'),
          source_url: l.source_url || '', source_minutes: Math.round((l.source_interval || 900) / 60), source_header: l.source_header || '',
          source_secret: '', secret_set: !!l.source_secret_set, stored_url: l.source_url || '' }
      : { name: '', kind: 'dynamic', description: '', text: '', source_url: '', source_minutes: 15, source_header: '', source_secret: '', secret_set: false, stored_url: '' };
  }
  // The control plane keeps a stored secret only for the same scheme, host
  // and path (another query is fine); for any other URL it must be typed again.
  function sameSource(a: string, b: string): boolean {
    try {
      const x = new URL(a), y = new URL(b.trim());
      return x.protocol === y.protocol && x.host === y.host && x.pathname === y.pathname;
    } catch { return false; }
  }
  const secretKept = $derived(!!editing && editing.secret_set && sameSource(editing.stored_url, editing.source_url));
  const entryCount = $derived(editing ? editing.text.split(/\r?\n/).map((s) => s.replace(/#.*/, '').trim()).filter(Boolean).length : 0);
  async function save() {
    if (!editing) return;
    busy = true;
    try {
      const url = editing.source_url.trim();
      const body = { name: editing.name.trim(), kind: editing.kind, description: editing.description.trim(), entries: editing.text.split(/\r?\n/),
        source_url: url, source_interval: url ? Math.max(1, editing.source_minutes) * 60 : 0, source_header: editing.source_header.trim(),
        // absent keeps the stored secret, "" clears it
        ...(editing.source_secret ? { source_secret: editing.source_secret } : editing.secret_set ? {} : { source_secret: '' }) };
      if (editing.id) await admin.putList(editing.id, body); else await admin.createList(body);
      toast(editing.id ? 'List saved; nodes pick it up within seconds' : 'List created', 'ok');
      editing = null;
      await load();
    } catch (e) { fail(e); } finally { busy = false; }
  }
  async function remove(l: AclList) {
    if (!window.confirm(`Delete list “${l.name}”?`)) return;
    try { await admin.deleteList(l.id); toast('Deleted', 'ok'); await load(); } catch (e) { fail(e); }
  }
  const preview = (l: AclList) => l.entries.slice(0, 6).join(', ') + (l.entries.length > 6 ? ` … +${l.entries.length - 6}` : '');

  // A list is a text file: it can be downloaded, committed to a repository
  // and read back, by hand or by the control plane (source url).
  async function exportList(l: AclList) {
    try {
      const text = await admin.exportList(l.id);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      a.download = l.name + '.list';
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) { fail(e); }
  }
  function pickFile(l: AclList) { importInto = l; fileInput?.click(); }
  async function importFile(ev: Event) {
    const input = ev.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    const l = importInto;
    input.value = '';
    if (!file || !l) return;
    const add = window.confirm(`Add ${file.name} to “${l.name}” (${l.entries.length} entries)?\n\nCancel replaces the list with the file.`);
    try {
      const out = await admin.importList(l.id, await file.text(), add ? 'add' : 'replace');
      toast(`${out.entries.length} entries in ${out.name}`, 'ok');
      await load();
    } catch (e) { fail(e); }
  }
  async function fetchNow(l: AclList) {
    fetching = l.id;
    try {
      const out = await admin.fetchList(l.id);
      toast(`Fetched: ${out.entries.length} entries`, 'ok');
      await load();
    } catch (e) { fail(e); await load(); } finally { fetching = null; }
  }
</script>

<div class="page-head">
  <div><h1>Lists</h1><div class="sub">Named sets of addresses, names, or both at once. A policy refers to one as <code>resource in BoundGate::List::"name"</code>: an allow-list in a permit, a block-list in a forbid or an exception. A <b>dynamic access list</b> follows the traffic: it answers the DNS query for a name it holds, opens what the answer named for that device, and still matches the TLS server name.</div></div>
  <div class="row"><a class="btn" href="/policies">Policies</a><button class="btn primary" onclick={() => start()}>+ New list</button></div>
</div>

{#if editing}
  <div class="card col" style="gap:12px; margin-bottom:16px">
    <h2>{editing.id ? `Edit ${editing.name}` : 'New list'}</h2>
    <div class="grid cols-2">
      <label class="field">Name <input placeholder="allowed-sites" bind:value={editing.name} disabled={!!editing.id && lists.find((l) => l.id === editing?.id)?.used_by.length! > 0} /></label>
      <label class="field">Kind
        <select bind:value={editing.kind} disabled={!!editing.id && lists.find((l) => l.id === editing?.id)?.used_by.length! > 0}>
          {#each Object.entries(kindLabel) as [k, label]}<option value={k}>{label}</option>{/each}
        </select>
      </label>
    </div>
    <label class="field">Description <input placeholder="what the list is for" bind:value={editing.description} /></label>
    <label class="field">Entries <span class="faint small">{entryCount}</span>
      <textarea class="code" rows="12" spellcheck="false" placeholder={editing.kind === 'ip' ? '10.60.0.11\n192.168.178.0/24' : editing.kind === 'dynamic' ? '*.github.com\n10.60.0.11:443  # comments are fine' : 'myip.wtf\n*.github.com  # comments are fine'} bind:value={editing.text}></textarea>
    </label>
    <div class="hint">{kindHelp[editing.kind]} Blank lines and everything after # are ignored; the list is sorted and de-duplicated on save. Up to 10 000 entries.</div>
    <details open={!!editing.source_url}>
      <summary class="small muted" style="cursor:pointer">Source: {editing.source_url ? 'follows a URL' : 'edited here'}</summary>
      <div class="col" style="gap:10px; margin-top:8px">
        <label class="field">URL <input class="mono" placeholder="https://git.example.com/acl/raw/branch/main/ad-domains.list" bind:value={editing.source_url} /></label>
        <div class="grid cols-2">
          <label class="field">Every <input type="number" min="1" max="10080" bind:value={editing.source_minutes} /><span class="hint">minutes; at least 1</span></label>
          <label class="field">Header for a private repository <input class="mono" placeholder="Private-Token" bind:value={editing.source_header} /></label>
        </div>
        <label class="field">Its value
          <input type="password" autocomplete="off" placeholder={secretKept ? '•••••••• (stored; type to replace)' : 'only for a private repository'} bind:value={editing.source_secret} />
          <span class="hint">Kept by the control plane and never sent back to this page. Leave empty to keep what is stored; save with an empty field and no stored value to clear it.
            {#if editing.secret_set && !secretKept}<strong>The URL points somewhere else now: the stored value (and the header) will be dropped on save. Type it again if the new address needs it.</strong>{/if}</span>
        </label>
        <div class="hint">With a URL the control plane fetches the file itself and replaces the entries with what it finds: one entry per line (# comments) or a JSON array, the same form as the export. A raw file URL of GitHub, GitLab or Gitea works. What you type above is only the starting point, and a file that cannot be read leaves the list as it is, with the reason under the list.</div>
      </div>
    </details>
    {#if editing.id && (lists.find((l) => l.id === editing?.id)?.used_by.length ?? 0) > 0}
      <div class="hint">Policies refer to this list, so its name and kind stay; the entries can change and take effect on every node within seconds.</div>
    {/if}
    <div class="row">
      <button class="btn primary" disabled={busy || !editing.name.trim()} onclick={save}>{editing.id ? 'Save' : 'Create'}</button>
      <button class="btn" onclick={() => (editing = null)}>Cancel</button>
    </div>
  </div>
{/if}

{#if loaded && lists.length === 0 && !editing}
  <div class="card empty">No lists yet. A list keeps the addresses or names apart from the rules that use them: block <code>ad-domains</code> for everyone, allow <code>allowed-sites</code> for one node, and edit the entries without touching a policy.</div>
{/if}
<input type="file" accept=".list,.txt,.json,text/plain,application/json" style="display:none" bind:this={fileInput} onchange={importFile} />
<div class="col" style="gap:12px">
  {#each lists as l (l.id)}
    <div class="card">
      <div class="row between" style="align-items:flex-start">
        <div class="grow">
          <div class="row"><b style="font-size:15px">{l.name}</b> <span class="chip">{kindLabel[l.kind]}</span> <span class="faint small">{l.entries.length} entries</span>
            {#if l.used_by.length}<span class="chip" title={l.used_by.join(', ')}>used by {l.used_by.length} {l.used_by.length === 1 ? 'policy' : 'policies'}</span>{:else}<span class="chip plain">not used</span>{/if}
          </div>
          {#if l.description}<div class="muted" style="margin-top:4px">{l.description}</div>{/if}
          <div class="mono small" style="margin-top:6px; word-break:break-all">{preview(l)}</div>
          <div class="faint small" style="margin-top:6px">updated <Time at={l.updated_at} /> by {l.updated_by === 'source' ? 'its source' : l.updated_by || l.created_by || '?'}</div>
          {#if l.source_url}
            <div class="small" style="margin-top:6px; word-break:break-all">
              <span class="chip">every {Math.round((l.source_interval || 0) / 60)} min</span>
              <span class="mono faint">{l.source_url}</span>
              {#if l.source_fetched_at}<span class="faint"> · last <Time at={l.source_fetched_at} /></span>{/if}
            </div>
            {#if l.source_status}<div class="error small" style="margin-top:4px">Source: {l.source_status} (the entries are the ones from before)</div>{/if}
          {/if}
        </div>
        <div class="row" style="gap:6px">
          {#if l.source_url}<button class="btn sm" disabled={fetching === l.id} onclick={() => fetchNow(l)}>{fetching === l.id ? 'Fetching…' : 'Fetch now'}</button>{/if}
          <button class="btn sm" onclick={() => exportList(l)}>Export</button>
          <button class="btn sm" onclick={() => pickFile(l)}>Import…</button>
          <button class="btn sm" onclick={() => start(l)}>Edit</button>
          <button class="btn sm danger" disabled={l.used_by.length > 0} title={l.used_by.length ? 'remove the policies that use it first' : ''} onclick={() => remove(l)}>Delete</button>
        </div>
      </div>
    </div>
  {/each}
</div>
