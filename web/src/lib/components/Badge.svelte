<script lang="ts">
  import { statusTone } from '../util';
  let { status, label }: { status: string; label?: string } = $props();
</script>
<span class="badge {statusTone(status)}">{label ?? status}</span>
