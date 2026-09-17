<script lang="ts">
  import { auth, refreshAuth, oidcLoginURL, logout } from '../lib/auth.svelte';
  import { setToken } from '../lib/api';
  import { registerPasskey, loginPasskey, passkeysSupported } from '../lib/webauthn';
  import { toast, fail } from '../lib/toast.svelte';
  import Logo from '../lib/components/Logo.svelte';
  import Icon from '../lib/components/Icon.svelte';

  let busy = $state(false);
  let label = $state('');
  let bootstrap = $state('');
  let token = $state('');
  let showToken = $state(false);
  let msg = $state('');
  const st = $derived(auth.status!);

  async function useToken() {
    busy = true;
    try {
      setToken(token.trim());
      const s = await refreshAuth();
      if (s.level !== 'full') { setToken(null); await refreshAuth(); msg = s.error || 'That token was not accepted.'; }
    } finally { busy = false; }
  }
  async function doRegister() {
    busy = true; msg = '';
    try {
      const r = await registerPasskey(label || 'my passkey', bootstrap);
      if (r.status === 'active') { toast('Passkey registered', 'ok'); await refreshAuth(); }
      else { msg = 'Your passkey is registered but waits for approval by another administrator. Reload this page once it is approved.'; await refreshAuth(); }
    } catch (e) { fail(e); } finally { busy = false; }
  }
  async function doLogin() {
    busy = true; msg = '';
    try { await loginPasskey(); await refreshAuth(); } catch (e) { fail(e); } finally { busy = false; }
  }
</script>

<div class="login-wrap">
  <svg class="motif" viewBox="96 216 832 592" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="57" stroke-linecap="round" stroke-linejoin="round"><rect x="148" y="268" width="462" height="300" rx="76" /><rect x="414" y="456" width="462" height="300" rx="76" /></g></svg>
  <div class="card login col" style="gap:14px">
    <div class="brand"><span class="tile"><Logo size={64} adaptive draw title="BoundGate" /></span> BoundGate</div>
    <div class="steps" aria-label="Sign-in steps">
      <span class="s {st.level === 'none' ? 'now' : 'done'}"><span class="dot">{st.level === 'none' ? '1' : '✓'}</span> Identity</span>
      <span class="bar"></span>
      <span class="s {st.level === 'oidc_only' ? 'now' : ''}"><span class="dot">2</span> Passkey</span>
      <span class="bar"></span>
      <span class="s"><span class="dot">3</span> Console</span>
    </div>

    {#if st.level === 'none'}
      <p class="muted" style="text-align:center">Administrators sign in with the organisation's identity provider, then prove possession of a registered passkey.</p>
      {#if st.oidc_configured}
        <a class="btn primary lg" href={oidcLoginURL('/')}>Sign in with SSO <Icon name="arrow" /></a>
      {:else}
        <p class="error">No identity provider is configured on this control plane (oidc.issuer).</p>
      {/if}
      {#if st.bootstrap_active}
        <div class="callout small">
          <b>First-time setup.</b> <span class="muted">No administrator passkey exists yet. Sign in with SSO as a member of the admin group and register the first passkey with the bootstrap token from the control plane's state directory. That token stops working afterwards.</span>
        </div>
      {/if}
      {#if st.error}<p class="error small">{st.error}</p>{/if}
      <div style="text-align:center">
        <button class="btn ghost sm" onclick={() => (showToken = !showToken)}>{showToken ? 'Hide' : 'Use an API token instead'}</button>
        {#if showToken}
          <div class="col" style="margin-top:8px; text-align:left">
            <input type="password" placeholder={st.bootstrap_active ? 'bgapi_… or the bootstrap token' : 'bgapi_…'} bind:value={token} onkeydown={(e) => e.key === 'Enter' && useToken()} />
            <button class="btn" disabled={busy || !token.trim()} onclick={useToken}>Continue</button>
            <span class="hint">Tokens are kept in this tab only. Create them under Admins → API tokens.</span>
          </div>
        {/if}
      </div>
      {#if msg}<p class="error small">{msg}</p>{/if}
    {:else}
      <div style="text-align:center">
        <div><b>{st.name || st.email || st.subject}</b></div>
        <div class="muted small">signed in via SSO · now confirm with a passkey</div>
      </div>
      {#if !passkeysSupported()}
        <p class="error">This browser does not support passkeys (WebAuthn).</p>
      {:else if !st.passkeys_enabled}
        <p class="error">Passkeys are not configured on this control plane (admin.rp_id).</p>
      {:else if st.own_passkeys > 0}
        <button class="btn primary lg" disabled={busy} onclick={doLogin}>{#if busy}<span class="spinner"></span> Waiting for the authenticator…{:else}<Icon name="passkey" /> Continue with passkey{/if}</button>
      {:else}
        {#if st.own_pending > 0}
          <div class="callout small"><b>Waiting for approval.</b> <span class="muted">Your passkey is registered; another administrator has to approve it under Admins → Passkeys.</span></div>
          <button class="btn" onclick={() => refreshAuth()}>Check again</button>
        {:else}
          <label class="field">Name this passkey <input placeholder="YubiKey 5C, MacBook Touch ID, …" bind:value={label} /></label>
          {#if st.bootstrap_active}
            <label class="field">Bootstrap token <input type="password" placeholder="from state/control/bootstrap.token" bind:value={bootstrap} />
              <span class="hint">Required for the very first passkey only.</span></label>
          {:else}
            <span class="hint">A passkey you register now needs approval by an existing administrator before it works.</span>
          {/if}
          <button class="btn primary lg" disabled={busy || (st.bootstrap_active && !bootstrap)} onclick={doRegister}>{#if busy}<span class="spinner"></span> Waiting for the authenticator…{:else}<Icon name="passkey" /> Register passkey{/if}</button>
        {/if}
      {/if}
      {#if msg}<p class="small muted">{msg}</p>{/if}
      <button class="btn ghost sm" style="align-self:center" onclick={() => logout()}>Sign out</button>
    {/if}
  </div>
</div>
