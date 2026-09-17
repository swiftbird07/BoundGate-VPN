<script lang="ts">
  // The BoundGate mark: two interlocked frames, two ends and one connection.
  // Geometry and colours come from the app icon (1024 grid, stroke 57).
  // tile: the mark on its charcoal ground, as in the app icon. adaptive
  // takes both colours from the theme (--logo-ground, --logo-mark): charcoal
  // tile on light surfaces, the icon's light variant (charcoal on yellow)
  // where the surface behind it is charcoal already. Without the tile the
  // mark takes the current text colour. draw: the frames draw themselves once.
  let { size = 32, tile = true, adaptive = false, draw = false, title = '' }: { size?: number; tile?: boolean; adaptive?: boolean; draw?: boolean; title?: string } = $props();
  const ground = $derived(adaptive ? 'var(--logo-ground)' : '#2A2A2A');
  const mark = $derived(!tile ? 'currentColor' : adaptive ? 'var(--logo-mark)' : '#FFCC00');
</script>

<svg class="bg-logo" class:draw width={size} height={size} viewBox={tile ? '0 0 1024 1024' : '96 216 832 592'} role={title ? 'img' : 'presentation'} aria-label={title || undefined} aria-hidden={title ? undefined : 'true'}>
  {#if tile}<rect width="1024" height="1024" rx="232" fill={ground} />{/if}
  <g fill="none" stroke={mark} stroke-width="57" stroke-linecap="round" stroke-linejoin="round">
    <rect class="a" x="148" y="268" width="462" height="300" rx="76" pathLength="1" />
    <rect class="b" x="414" y="456" width="462" height="300" rx="76" pathLength="1" />
  </g>
</svg>

<style>
  .bg-logo { display: block; flex: none; }
  .draw rect.a, .draw rect.b { stroke-dasharray: 1; stroke-dashoffset: 1; opacity: 0; animation: bg-draw .9s cubic-bezier(.6, 0, .2, 1) forwards; }
  .draw rect.b { animation-delay: .25s; }
  @keyframes bg-draw { 0% { opacity: 0; } 8% { opacity: 1; } 100% { opacity: 1; stroke-dashoffset: 0; } }
  @media (prefers-reduced-motion: reduce) { .draw rect.a, .draw rect.b { animation: none; stroke-dashoffset: 0; opacity: 1; } }
</style>
