<script lang="ts">
  import { onMount } from 'svelte';
  import { admin } from '../lib/api';
  import { auth, refreshAuth } from '../lib/auth.svelte';
  import { registerPasskey, passkeysSupported } from '../lib/webauthn';
  import type { Passkey, Signer, ApiToken } from '../lib/types';
  import Time from '../lib/components/Time.svelte';
  import Badge from '../lib/components/Badge.svelte';
  import Copy from '../lib/components/Copy.svelte';
  import Dialog from '../lib/components/Dialog.svelte';
  import { toast, fail } from '../lib/toast.svelte';

  let passkeys = $state<Passkey[]>([]);
  let signers = $state<Signer[]>([]);
  let tokens = $state<ApiToken[]>([]);
  let showRevoked = $state(false);
  let newSigner = $state({ name: '', key: '' });
  let newToken = $state({ name: '', expires: '720h' });
  let minted = $state<ApiToken | null>(null);
  let pkLabel = $state('');
  let busy = $state(false);
  async function load() { try { [passkeys, signers, tokens] = await Promise.all([admin.passkeys(), admin.signers(), admin.tokens()]); } catch (e) { fail(e); } }
  onMount(() => { void load(); });
  const me = $derived(auth.status?.subject);

  async function approve(p: Passkey) { try { await admin.approvePasskey(p.id); toast('Passkey approved', 'ok'); await load(); } catch (e) { fail(e); } }
  async function revokePk(p: Passkey) { if (!window.confirm(`Revoke passkey “${p.label}” of ${p.email || p.subject}?`)) return; try { await admin.revokePasskey(p.id); toast('Passkey revoked', 'ok'); await load(); await refreshAuth(); } catch (e) { fail(e); } }
  async function addPasskey() {
    busy = true;
    try { const r = await registerPasskey(pkLabel || 'passkey', ''); toast(r.status === 'active' ? 'Passkey added' : 'Passkey registered; another admin must approve it', 'ok'); pkLabel = ''; await load(); await refreshAuth(); } catch (e) { fail(e); } finally { busy = false; }
  }
  async function addSigner() { try { await admin.addSigner(newSigner.name, newSigner.key.trim()); toast('Signing key registered', 'ok'); newSigner = { name: '', key: '' }; await load(); } catch (e) { fail(e); } }
  async function revokeSigner(s: Signer) { if (!window.confirm(`Revoke signing key “${s.name}”? Existing signatures stay valid; new bindings cannot be signed with it.`)) return; try { await admin.revokeSigner(s.id); await load(); } catch (e) { fail(e); } }
  async function createToken() { try { minted = await admin.createToken(newToken.name, newToken.expires); newToken = { name: '', expires: '720h' }; await load(); } catch (e) { fail(e); } }
  async function revokeToken(t: ApiToken) { if (!window.confirm(`Revoke API token “${t.name}”?`)) return; try { await admin.revokeToken(t.id); await load(); } catch (e) { fail(e); } }
</script>

<div class="page-head">
  <div><h1>Administrators</h1><div class="sub">Who may operate this control plane: passkeys for people, signing keys for approvals, tokens for automation.</div></div>
  <label class="check"><input type="checkbox" bind:checked={showRevoked} /> show revoked</label>
</div>

<div class="col" style="gap:14px">
  <div class="card">
    <div class="card-title"><h2>Passkeys</h2>
      {#if auth.status?.via === 'session' && passkeysSupported()}
        <div class="row"><input placeholder="name for a new passkey" bind:value={pkLabel} /><button class="btn sm primary" disabled={busy} onclick={addPasskey}>Add passkey for me</button></div>
      {/if}
    </div>
    <p class="small muted">An admin signs in with SSO and confirms with one of these. New passkeys of another admin need approval here; your own additional passkeys are active immediately. {#if auth.status?.bootstrap_active}<b class="error">No active passkey exists yet, so the bootstrap token still works.</b>{/if}</p>
    <table>
      <thead><tr><th>Admin</th><th>Passkey</th><th>Status</th><th>Registered</th><th>Last used</th><th></th></tr></thead>
      <tbody>
        {#each passkeys.filter((p) => showRevoked || p.status !== 'revoked') as p (p.id)}
          <tr>
            <td><b>{p.email || p.subject}</b>{#if p.subject === me} <span class="chip">you</span>{/if}<div class="faint small">{p.subject}</div></td>
            <td>{p.label || '–'}</td>
            <td><Badge status={p.status} />{#if p.approved_by}<div class="faint small">approved by {p.approved_by}</div>{/if}{#if p.revoked_by}<div class="faint small">revoked by {p.revoked_by}</div>{/if}</td>
            <td><Time at={p.created_at} /></td>
            <td><Time at={p.last_used_at} /></td>
            <td><div class="row" style="justify-content:flex-end; flex-wrap:nowrap">
              {#if p.status === 'pending' && p.subject !== me}<button class="btn sm primary" onclick={() => approve(p)}>Approve</button>{/if}
              {#if p.status !== 'revoked'}<button class="btn sm danger" onclick={() => revokePk(p)}>Revoke</button>{/if}
            </div></td>
          </tr>
        {:else}<tr><td colspan="6" class="empty">No passkeys registered.</td></tr>{/each}
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title"><h2>Admin signing keys</h2></div>
    <p class="small muted">SSH keys (YubiKey <code>sk-ssh-ed25519</code> or software ed25519) that sign node bindings via <code>boundgatectl admin sign</code>. Nodes pin this list at enrollment.</p>
    <table>
      <thead><tr><th>Name</th><th>Key</th><th>Type</th><th>Added</th><th></th></tr></thead>
      <tbody>
        {#each signers.filter((s) => showRevoked || !s.revoked_at) as s (s.id)}
          <tr>
            <td><b>{s.name}</b>{#if s.revoked_at}<div><Badge status="revoked" /></div>{/if}</td>
            <td class="mono small">{s.fingerprint}</td>
            <td>{s.key_type}{#if s.hardware} <span class="chip">hardware</span>{/if}</td>
            <td><Time at={s.created_at} /></td>
            <td style="text-align:right">{#if !s.revoked_at}<button class="btn sm danger" onclick={() => revokeSigner(s)}>Revoke</button>{/if}</td>
          </tr>
        {:else}<tr><td colspan="5" class="empty">No signing key: nodes cannot be approved.</td></tr>{/each}
      </tbody>
    </table>
    <div class="row" style="margin-top:12px; align-items:flex-end">
      <label class="field">Name <input placeholder="Martin's YubiKey" bind:value={newSigner.name} /></label>
      <label class="field grow">Public key (authorized_keys line) <input class="mono" placeholder="sk-ssh-ed25519@openssh.com AAAA… comment" bind:value={newSigner.key} /></label>
      <button class="btn" disabled={!newSigner.key.trim()} onclick={addSigner}>Register key</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title"><h2>API tokens</h2></div>
    <p class="small muted">Bearer tokens with full admin rights for scripts and CI (<code>Authorization: Bearer bgapi_…</code>). The secret is shown once.</p>
    <table>
      <thead><tr><th>Name</th><th>Created</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
      <tbody>
        {#each tokens.filter((t) => showRevoked || !t.revoked_at) as t (t.id)}
          <tr>
            <td><b>{t.name}</b>{#if t.revoked_at} <Badge status="revoked" />{/if}<div class="faint small">by {t.created_by}</div></td>
            <td><Time at={t.created_at} /></td><td>{#if t.expires_at}<Time at={t.expires_at} />{:else}<span class="faint">never</span>{/if}</td><td><Time at={t.last_used_at} /></td>
            <td style="text-align:right">{#if !t.revoked_at}<button class="btn sm danger" onclick={() => revokeToken(t)}>Revoke</button>{/if}</td>
          </tr>
        {:else}<tr><td colspan="5" class="empty">No API tokens.</td></tr>{/each}
      </tbody>
    </table>
    <div class="row" style="margin-top:12px; align-items:flex-end">
      <label class="field">Name <input placeholder="ci-deploy" bind:value={newToken.name} /></label>
      <label class="field">Expires in <select bind:value={newToken.expires}><option value="24h">1 day</option><option value="168h">1 week</option><option value="720h">30 days</option><option value="8760h">1 year</option><option value="">never</option></select></label>
      <button class="btn" disabled={!newToken.name.trim()} onclick={createToken}>Create token</button>
    </div>
  </div>
</div>

{#if minted}
  <Dialog title="API token created" onclose={() => (minted = null)}>
    <p class="muted">Copy it now; it will not be shown again.</p>
    <div class="cmd"><pre>{minted.token}</pre><Copy text={minted.token || ''} /></div>
    {#snippet footer()}<button class="btn primary" onclick={() => (minted = null)}>Done</button>{/snippet}
  </Dialog>
{/if}
