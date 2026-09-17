<script lang="ts">
  import { copy } from '../util';
  import { toast } from '../toast.svelte';
  let { text, label = 'Copy' }: { text: string; label?: string } = $props();
  let done = $state(false);
  async function go() {
    done = await copy(text);
    if (!done) toast('Clipboard unavailable; select the text instead', 'bad');
    setTimeout(() => (done = false), 1500);
  }
</script>
<button class="btn sm" onclick={go}>{done ? '✓ Copied' : label}</button>
