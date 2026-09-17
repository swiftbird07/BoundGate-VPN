<script lang="ts">
  import { toasts } from '../toast.svelte';
  import Icon from './Icon.svelte';
</script>
<div class="toasts">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}">
      <Icon name={t.kind === 'ok' ? 'check' : t.kind === 'bad' ? 'alert' : 'info'} />
      <span>{t.text}</span>
    </div>
  {/each}
</div>
