<script lang="ts">
  import { onMount } from 'svelte';
  import { auth, refreshAuth, logout } from './lib/auth.svelte';
  import { route } from './lib/router.svelte';
  import { admin } from './lib/api';
  import type { Overview } from './lib/types';
  import Toasts from './lib/components/Toasts.svelte';
  import Logo from './lib/components/Logo.svelte';
  import Icon, { type IconName } from './lib/components/Icon.svelte';
  import Login from './pages/Login.svelte';
  import OverviewPage from './pages/Overview.svelte';
  import Nodes from './pages/Nodes.svelte';
  import Mesh from './pages/Mesh.svelte';
  import Sessions from './pages/Sessions.svelte';
  import Policies from './pages/Policies.svelte';
  import Lists from './pages/Lists.svelte';
  import PolicyEditor from './pages/PolicyEditor.svelte';
  import Logs from './pages/Logs.svelte';
  import Admins from './pages/Admins.svelte';
  import Settings from './pages/Settings.svelte';

  let theme = $state<'dark' | 'light' | 'system'>('system');
  let counts = $state<Overview | null>(null);

  function applyTheme(t: typeof theme) {
    theme = t;
    if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('bg_theme', t); } catch { /* ignore */ }
  }
  function cycleTheme() { applyTheme(theme === 'system' ? 'dark' : theme === 'dark' ? 'light' : 'system'); }

  async function loadCounts() {
    if (auth.status?.level !== 'full') return;
    try { counts = await admin.overview(); } catch { /* shown on the page */ }
  }

  onMount(() => {
    try { applyTheme((localStorage.getItem('bg_theme') as typeof theme) || 'system'); } catch { /* ignore */ }
    void refreshAuth().then(loadCounts);
    const t = setInterval(loadCounts, 15000);
    return () => clearInterval(t);
  });
  $effect(() => { if (auth.status?.level === 'full') void loadCounts(); });

  const nav: { href: string; label: string; icon: IconName; badge?: () => number }[] = [
    { href: '/', label: 'Overview', icon: 'overview' },
    { href: '/nodes', label: 'Nodes', icon: 'nodes', badge: () => (counts?.nodes?.pending ?? 0) + (counts?.nodes?.confirmed ?? 0) },
    { href: '/mesh', label: 'Mesh', icon: 'mesh' },
    { href: '/sessions', label: 'Sessions', icon: 'sessions' },
    { href: '/policies', label: 'Policies', icon: 'policies' },
    { href: '/lists', label: 'Lists', icon: 'lists' },
    { href: '/logs', label: 'Logs', icon: 'logs' },
    { href: '/admins', label: 'Admins', icon: 'admins', badge: () => counts?.pending_passkeys ?? 0 },
    { href: '/settings', label: 'Settings', icon: 'settings' },
  ];
  const who = $derived(auth.status?.name || auth.status?.email || auth.status?.subject || '');
  const initials = $derived((who.match(/[\p{L}\p{N}]+/gu) ?? ['?']).slice(0, 2).map((w) => w[0]).join(''));
  const active = (href: string) => (href === '/' ? route.path === '/' : route.path.startsWith(href));
  const page = $derived.by(() => {
    const p = route.path;
    if (p === '/') return OverviewPage;
    if (p.startsWith('/nodes')) return Nodes;
    if (p.startsWith('/mesh')) return Mesh;
    if (p.startsWith('/sessions')) return Sessions;
    if (p.startsWith('/policies/')) return PolicyEditor;
    if (p.startsWith('/policies')) return Policies;
    if (p.startsWith('/lists')) return Lists;
    if (p.startsWith('/logs')) return Logs;
    if (p.startsWith('/admins')) return Admins;
    if (p.startsWith('/settings')) return Settings;
    return OverviewPage;
  });
</script>

<Toasts />
{#if auth.loading}
  <div class="login-wrap"><div class="splash"><Logo size={72} adaptive draw /><span>Connecting…</span></div></div>
{:else if auth.status?.level !== 'full'}
  <Login />
{:else}
  <div class="shell">
    <nav class="sidebar">
      <a class="brand" href="/"><span class="tile"><Logo size={34} adaptive title="BoundGate" /></span> BoundGate</a>
      <div class="nav col" style="gap:2px">
        {#each nav as n}
          <a href={n.href} class:active={active(n.href)}>
            <Icon name={n.icon} />{n.label}
            {#if n.badge && n.badge() > 0}<span class="cnt">{n.badge()}</span>{/if}
          </a>
        {/each}
      </div>
      <div class="nav-foot col" style="gap:8px">
        <div class="who">
          <span class="avatar">{initials}</span>
          <div class="grow">
            <div class="ellipsis" title={auth.status?.subject}><b>{who}</b></div>
            <div class="faint small">{auth.status?.via === 'session' ? 'SSO + passkey' : auth.status?.via === 'token' ? 'API token' : 'bootstrap token'}</div>
          </div>
        </div>
        <div class="row" style="gap:4px">
          <button class="btn sm ghost" onclick={cycleTheme} title="Theme: {theme} (click to change)" aria-label="Theme: {theme}"><Icon name={theme === 'dark' ? 'moon' : theme === 'light' ? 'sun' : 'auto'} size={16} /></button>
          <button class="btn sm ghost" onclick={() => logout()}><Icon name="logout" size={16} /> Sign out</button>
        </div>
      </div>
    </nav>
    <main class="main">
      {#key route.path}
        {@const Page = page}
        <div class="page"><Page /></div>
      {/key}
    </main>
  </div>
{/if}
