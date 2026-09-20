<script lang="ts">
  // The control plane's sign command, made runnable where the admin sits: the
  // path of boundgatectl (not on PATH when it came inside the Mac app) and
  // the key file for --key. Both are remembered in this browser only.
  import Copy from './Copy.svelte';
  let { command }: { command: string } = $props();

  const mac = typeof navigator !== 'undefined' && /Mac/i.test(navigator.platform || navigator.userAgent);
  const defaults = { bin: mac ? '/Applications/BoundGate.app/Contents/MacOS/boundgatectl' : 'boundgatectl', key: '~/.ssh/id_boundgate_sk' };
  function recall(k: 'bin' | 'key'): string { try { return localStorage.getItem('bg.sign.' + k) ?? defaults[k]; } catch { return defaults[k]; } }
  function remember(k: 'bin' | 'key', v: string) { try { localStorage.setItem('bg.sign.' + k, v); } catch { /* private window: works without */ } }
  let bin = $state(recall('bin'));
  let key = $state(recall('key'));
  $effect(() => remember('bin', bin));
  $effect(() => remember('key', key));

  const quote = (s: string) => (/^[A-Za-z0-9_\/.~:-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
  const full = $derived(command.replace(/^boundgatectl\b/, quote(bin.trim() || 'boundgatectl')) + (key.trim() ? ' --key ' + quote(key.trim()) : ''));
</script>

<div class="cmd"><pre>{full}</pre><Copy text={full} /></div>
<details class="adjust">
  <summary>boundgatectl path and key file</summary>
  <div class="grid cols-2" style="margin-top:8px">
    <label class="field">boundgatectl <input class="mono" bind:value={bin} placeholder={defaults.bin} /></label>
    <label class="field">Key file (--key) <input class="mono" bind:value={key} placeholder="empty: ask ssh-agent" /></label>
  </div>
  <p class="hint">Inside the Mac app boundgatectl is at <code>/Applications/BoundGate.app/Contents/MacOS/boundgatectl</code>. With <code>--key</code> the file is used then and there (passphrase, FIDO PIN, touch); without it the command asks ssh-agent.</p>
</details>

<style>
  .adjust { margin-top: 6px; }
  .adjust summary { cursor: pointer; font-size: 12px; color: var(--text-3); }
  .adjust summary:hover { color: var(--text); }
</style>
