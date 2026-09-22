<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import type { AclList, ListKind } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import { toast, fail } from '../lib/toast.svelte';

  let lists = $state<AclList[]>([]);
  let loaded = $state(false);
  // the editor: a new list, or a copy of an existing one
  let editing = $state<{ id?: string; name: string; kind: ListKind; description: string; text: string } | null>(null);
  let busy = $state(false);
  const kindLabel: Record<ListKind, string> = { ip: 'Addresses', dns: 'DNS names', sni: 'TLS server names' };
  const kindHelp: Record<ListKind, string> = {
    ip: 'One address or CIDR prefix per line: 10.60.0.11, 192.168.178.0/24.',
    dns: 'One name per line. *.example.com matches every name under example.com (not example.com itself). Matched against the question of DNS queries.',
    sni: 'One name per line, * at the start matches any number of labels. Matched against the TLS ClientHello; a permit by such a list decides after the handshake (docs/ACL.md).',
  };

  async function load() { try { lists = await admin.lists(); } catch (e) { fail(e); } loaded = true; }
  onMount(() => { void load(); });

  function start(l?: AclList) {
    editing = l ? { id: l.id, name: l.name, kind: l.kind, description: l.description || '', text: l.entries.join('\n') }
                : { name: '', kind: 'sni', description: '', text: '' };
  }
  const entryCount = $derived(editing ? editing.text.split(/\r?\n/).map((s) => s.replace(/#.*/, '').trim()).filter(Boolean).length : 0);
  async function save() {
    if (!editing) return;
    busy = true;
    try {
      const body = { name: editing.name.trim(), kind: editing.kind, description: editing.description.trim(), entries: editing.text.split(/\r?\n/) };
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
</script>

<div class="page-head">
  <div><h1>Lists</h1><div class="sub">Named sets of addresses, DNS names or TLS server names. A policy refers to one as <code>resource in BoundGate::List::"name"</code>: an allow-list in a permit, a block-list in a forbid or an exception.</div></div>
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
      <textarea class="code" rows="12" spellcheck="false" placeholder={editing.kind === 'ip' ? '10.60.0.11\n192.168.178.0/24' : 'myip.wtf\n*.github.com  # comments are fine'} bind:value={editing.text}></textarea>
    </label>
    <div class="hint">{kindHelp[editing.kind]} Blank lines and everything after # are ignored; the list is sorted and de-duplicated on save. Up to 10 000 entries.</div>
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
          <div class="faint small" style="margin-top:6px">updated <Time at={l.updated_at} /> by {l.updated_by || l.created_by || '?'}</div>
        </div>
        <div class="row" style="gap:6px">
          <button class="btn sm" onclick={() => start(l)}>Edit</button>
          <button class="btn sm danger" disabled={l.used_by.length > 0} title={l.used_by.length ? 'remove the policies that use it first' : ''} onclick={() => remove(l)}>Delete</button>
        </div>
      </div>
    </div>
  {/each}
</div>
