<script lang="ts" module>
  // Line icons in the weight of the mark: 24 grid, round caps and joins.
  const paths = {
    overview: '<rect x="3.5" y="3.5" width="7" height="7" rx="2.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="2.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="2.2"/><rect x="13.5" y="13.5" width="7" height="7" rx="2.2"/>',
    nodes: '<circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="6" r="2.6"/><circle cx="18" cy="18" r="2.6"/><path d="M8.4 10.8l7.2-3.6M8.4 13.2l7.2 3.6"/>',
    mesh: '<circle cx="12" cy="12" r="2.8"/><circle cx="5" cy="5.5" r="2"/><circle cx="19" cy="5.5" r="2"/><circle cx="5" cy="18.5" r="2"/><circle cx="19" cy="18.5" r="2"/><path d="M6.5 7l3.4 3.1M17.5 7l-3.4 3.1M6.5 17l3.4-3.1M17.5 17l-3.4-3.1"/>',
    sessions: '<circle cx="12" cy="8" r="3.8"/><path d="M4.5 20c.4-3.8 3.4-5.8 7.5-5.8s7.1 2 7.5 5.8"/>',
    policies: '<path d="M12 3l7.5 2.8v5.7c0 4.8-3.2 8-7.5 9.5-4.3-1.5-7.5-4.7-7.5-9.5V5.8z"/><path d="M8.8 12l2.2 2.2 4.2-4.4"/>',
    lists: '<path d="M9.5 7h10M9.5 12h10M9.5 17h10"/><path d="M4.5 6l1.2 1.2L7.8 5M4.5 11l1.2 1.2L7.8 10M4.5 16l1.2 1.2L7.8 15"/>',
    logs: '<path d="M8.5 6.5h11M8.5 12h11M8.5 17.5h11"/><path d="M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01"/>',
    admins: '<circle cx="8" cy="15.5" r="4"/><path d="M11 12.5l8.5-8.5M16 7.5l2.8 2.8"/>',
    settings: '<path d="M4 7.5h9M19 7.5h1M4 16.5h1M11 16.5h9"/><circle cx="16" cy="7.5" r="2.5"/><circle cx="8" cy="16.5" r="2.5"/>',
    sun: '<circle cx="12" cy="12" r="3.8"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4"/>',
    moon: '<path d="M20 14.2A8.2 8.2 0 1 1 9.8 4a6.6 6.6 0 0 0 10.2 10.2z"/>',
    auto: '<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5v17"/><path d="M12 7.5a4.5 4.5 0 0 1 0 9z" fill="currentColor" stroke="none"/>',
    logout: '<path d="M9.5 4.5h-3a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h3"/><path d="M14.5 8l4 4-4 4M18.5 12h-9"/>',
    close: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
    refresh: '<path d="M19.5 12a7.5 7.5 0 1 1-2.3-5.4"/><path d="M19.5 4.5v4h-4"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    alert: '<path d="M12 4l9 15.5H3z"/><path d="M12 10v4.5M12 17.2h.01"/>',
    info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5M12 7.8h.01"/>',
    arrow: '<path d="M5 12h14M13.5 6.5L19 12l-5.5 5.5"/>',
    passkey: '<circle cx="9" cy="8" r="3.5"/><path d="M3 20c.3-3.5 2.7-5.3 6-5.3 1 0 2 .2 2.8.5"/><circle cx="17.5" cy="12.5" r="2.5"/><path d="M17.5 15v6l1.8-1.5"/>',
  } as const;
  export type IconName = keyof typeof paths;
</script>

<script lang="ts">
  let { name, size = 18 }: { name: IconName; size?: number } = $props();
</script>

<svg class="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{@html paths[name]}</svg>

<style>
  .icon { display: block; flex: none; }
</style>
