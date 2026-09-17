<script lang="ts">
  import { toasts } from '../toast.svelte';
</script>
<div class="toasts">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}">
      <span>{t.kind === 'ok' ? '✓' : t.kind === 'bad' ? '✕' : 'ⓘ'}</span>
      <span>{t.text}</span>
    </div>
  {/each}
</div>
