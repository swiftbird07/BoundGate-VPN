<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, onclose, children }: { title: string; onclose: () => void; children: Snippet } = $props();
  function key(e: KeyboardEvent) { if (e.key === 'Escape' && !document.querySelector('.dialog')) onclose(); }
</script>

<svelte:window onkeydown={key} />
<div class="backdrop" onclick={onclose} role="presentation"></div>
<aside class="drawer" aria-label={title}>
  <div class="row between" style="margin-bottom:14px">
    <h2>{title}</h2>
    <button class="btn ghost icon" onclick={onclose} aria-label="Close">✕</button>
  </div>
  {@render children()}
</aside>
