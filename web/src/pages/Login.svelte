<script lang="ts">
  import { auth, refreshAuth, oidcLoginURL, logout } from '../lib/auth.svelte';
  import { setToken } from '../lib/api';
  import { registerPasskey, loginPasskey, passkeysSupported } from '../lib/webauthn';
  import { toast, fail } from '../lib/toast.svelte';

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
  <div class="card login col" style="gap:14px">
    <div class="brand"><span class="logo">🛡</span> BoundGate</div>
    <div class="steps">
      <span class="s {st.level === 'none' ? 'now' : 'done'}"><span class="dot"></span> Identity</span>
      <span>›</span>
      <span class="s {st.level === 'oidc_only' ? 'now' : ''}"><span class="dot"></span> Passkey</span>
      <span>›</span>
      <span class="s"><span class="dot"></span> Console</span>
    </div>

    {#if st.level === 'none'}
      <p class="muted" style="text-align:center">Administrators sign in with the organisation's identity provider, then prove possession of a registered passkey.</p>
      {#if st.oidc_configured}
        <a class="btn primary" style="justify-content:center" href={oidcLoginURL('/')}>Sign in with SSO</a>
      {:else}
        <p class="error">No identity provider is configured on this control plane (oidc.issuer).</p>
      {/if}
      {#if st.bootstrap_active}
        <div class="card tight" style="border-color: rgba(251,191,36,.4)">
          <b>First-time setup.</b> <span class="muted">No administrator passkey exists yet. Sign in with SSO as a member of the admin group and register the first passkey with the bootstrap token from the control plane's state directory. That token stops working afterwards.</span>
        </div>
      {/if}
      {#if st.error}<p class="error small">{st.error}</p>{/if}
      <div>
        <button class="btn ghost sm" onclick={() => (showToken = !showToken)}>{showToken ? 'Hide' : 'Use an API token instead'}</button>
        {#if showToken}
          <div class="col" style="margin-top:8px">
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
        <button class="btn primary" style="justify-content:center" disabled={busy} onclick={doLogin}>{busy ? 'Waiting for the authenticator…' : 'Continue with passkey'}</button>
      {:else}
        {#if st.own_pending > 0}
          <div class="card tight" style="border-color: rgba(251,191,36,.4)"><b>Waiting for approval.</b> <span class="muted">Your passkey is registered; another administrator has to approve it under Admins → Passkeys.</span></div>
          <button class="btn" onclick={() => refreshAuth()}>Check again</button>
        {:else}
          <label class="field">Name this passkey <input placeholder="YubiKey 5C, MacBook Touch ID, …" bind:value={label} /></label>
          {#if st.bootstrap_active}
            <label class="field">Bootstrap token <input type="password" placeholder="from state/control/bootstrap.token" bind:value={bootstrap} />
              <span class="hint">Required for the very first passkey only.</span></label>
          {:else}
            <span class="hint">A passkey you register now needs approval by an existing administrator before it works.</span>
          {/if}
          <button class="btn primary" style="justify-content:center" disabled={busy || (st.bootstrap_active && !bootstrap)} onclick={doRegister}>{busy ? 'Waiting for the authenticator…' : 'Register passkey'}</button>
        {/if}
      {/if}
      {#if msg}<p class="small muted">{msg}</p>{/if}
      <button class="btn ghost sm" onclick={() => logout()}>Sign out</button>
    {/if}
  </div>
</div>
