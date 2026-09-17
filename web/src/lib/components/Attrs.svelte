<script lang="ts">
  let { attrs, skip = [] }: { attrs?: Record<string, unknown>; skip?: string[] } = $props();
  const entries = $derived(Object.entries(attrs ?? {}).filter(([k, v]) => !skip.includes(k) && v !== '' && v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0)));
  const show = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));
</script>
<span class="row" style="gap:4px">
  {#each entries as [k, v]}
    <span class="chip mono" title={k}>{k}={show(v)}</span>
  {/each}
</span>
