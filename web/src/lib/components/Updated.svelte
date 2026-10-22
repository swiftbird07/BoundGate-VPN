<script lang="ts">
  // What the page head says about its own freshness: when the last round of
  // the poll loop (lib/poll.ts) worked, what went wrong if it did not, and a
  // button to ask now. The clock ticks here so "3 s ago" stays true without
  // the page re-rendering.
  import { onMount } from 'svelte';
  import Icon from './Icon.svelte';
  import type { PollState } from '../poll';

  let { info, refresh }: { info: PollState; refresh: () => void } = $props();
  let tick = $state(0);
  onMount(() => { const t = setInterval(() => tick++, 1000); return () => clearInterval(t); });

  const label = $derived.by(() => {
    tick; // re-read every second
    if (!info.updatedAt) return info.busy ? 'loading…' : '';
    const s = Math.round((Date.now() - info.updatedAt) / 1000);
    if (s < 5) return 'updated just now';
    if (s < 60) return `updated ${s} s ago`;
    if (s < 3600) return `updated ${Math.round(s / 60)} min ago`;
    return `updated ${Math.round(s / 3600)} h ago`;
  });
</script>

<div class="row" style="gap:8px; align-items:center">
  {#if info.error}
    <span class="faint small" title={info.error} style="color:var(--bad)">not up to date</span>
  {:else}
    <span class="faint small nowrap">{label}</span>
  {/if}
  <button class="btn sm" onclick={refresh} disabled={info.busy} title="Ask the control plane now">
    {#if info.busy}<span class="spinner" style="width:13px;height:13px;border-width:2px"></span>{:else}<Icon name="refresh" size={14} />{/if}
    Refresh
  </button>
</div>
