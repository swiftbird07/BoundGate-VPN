# Design

The look of BoundGate follows its mark: two interlocked frames, two ends and
one connection.

## Mark

| | |
|---|---|
| Ground | `#2A2A2A` (charcoal) |
| Mark | `#FFCC00` (signal yellow) |
| Geometry | 1024 grid; two rounded frames 462 × 300, radius 76, at (148, 268) and (414, 456) |
| Stroke | 57 / 1024, round caps and joins, no filled areas |

`docs/assets/logo.svg` is the tile (mark on charcoal, corner radius 232). The
light variant swaps the two colours. In the admin UI the mark is the component
`web/src/lib/components/Logo.svelte`: `tile` draws the ground, `adaptive` takes
both colours from the theme (charcoal tile on light surfaces, yellow tile where
the surface is charcoal already), `draw` lets the frames draw themselves once.
The favicon uses a heavier stroke (70) so the mark holds at 16 px.

## Rules

* Flat surfaces. No gradients, no glass blur, no glow. Depth comes from one
  soft shadow and from surface steps (`--bg` → `--panel` → `--panel-2`).
* Yellow is a fill and a marker: primary buttons, the active navigation bar,
  counters, focus rings, the "needs attention" state. Text on yellow is always
  charcoal (`--on-accent`). Yellow is never body text on a light ground; links
  in the light theme are charcoal with a yellow underline.
* Because yellow is the brand, it does not mean "warning". Warnings are orange
  (`--warn`), errors red, success green, information blue.
* Radii are generous (14 px cards, 10 px controls, pills for badges) and line
  ends are round, like the mark. Icons (`Icon.svelte`) are 24-grid line icons
  with stroke 2 and round caps; no emoji or text glyphs as icons.
* Headings, the wordmark and large numbers use the rounded system face
  (`--display`: `ui-rounded`), everything else the system sans. No web fonts:
  the control plane serves the UI with `default-src 'self'`.
* The sidebar keeps the charcoal ground in both themes; it carries the brand.
* Motion is short (≤ 200 ms) and honours `prefers-reduced-motion`.

All tokens live at the top of `web/src/app.css`; pages use classes and tokens,
not colours. The pages the control plane renders itself around a login
(`loginPage` in `internal/control/api/login.go`) carry the same look inline.

## Working on the UI

```
make web-dev        # Vite in the box image, http://localhost:5183
```

`/?demo` answers the admin API from memory (`web/src/dev/demo.ts`): a small
fleet with pending and confirmed nodes, tunnels, sessions, policies, logs;
tunnel counters move and one tunnel flaps, for the mesh view (MESH.md).
`?demo=login`, `?demo=first` and `?demo=passkey` show the sign-in steps,
`?demo=off` returns to the real API (proxied to the lab, see
`web/vite.config.ts`). The demo layer is loaded in dev builds only; `make web`
does not bundle it.
