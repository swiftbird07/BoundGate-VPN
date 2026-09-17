<script lang="ts">
  import { ago, when } from '../util';
  let { at }: { at?: string | null } = $props();
</script>
{#if at}<span class="nowrap" title={when(at)}>{ago(at)}</span>{:else}<span class="faint">–</span>{/if}
