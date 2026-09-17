<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  let { title, onclose, children, footer, wide = false }: { title: string; onclose: () => void; children: Snippet; footer?: Snippet; wide?: boolean } = $props();
  function key(e: KeyboardEvent) { if (e.key === 'Escape') onclose(); }
</script>

<svelte:window onkeydown={key} />
<div class="backdrop top" onclick={onclose} role="presentation"></div>
<div class="dialog" role="dialog" aria-modal="true" aria-label={title} style={wide ? 'width:min(960px, calc(100vw - 32px))' : ''}>
  <div class="row between" style="margin-bottom:14px">
    <h2>{title}</h2>
    <button class="btn ghost icon" onclick={onclose} aria-label="Close"><Icon name="close" /></button>
  </div>
  {@render children()}
  {#if footer}
    <div class="row" style="justify-content:flex-end; margin-top:18px">{@render footer()}</div>
  {/if}
</div>
