# Mesh view

`/mesh` in the admin UI draws the overlay: every approved node, the tunnels
between them right now, and what was connected at any moment of the last hour,
day or week.

## What it shows

| Element | Meaning |
|---|---|
| Node | one approved node. The glyph is its kind: hub, subnet router, exit node, laptop (interactive endpoint), server (workload). A hub that is also an exit node carries a small globe |
| Green ring, breathing | the node sent a heartbeat in the last 90 s. A dashed, dimmed disc is an approved node that did not |
| Yellow badge | hardware-bound device key (TPM, Secure Enclave), as granted in the signed binding |
| Blue badge with a letter | a user is signed in on the node |
| Dashed box on a dotted line | a prefix the node announces (`routed` or masqueraded) |
| Dotted line, moving | an open tunnel. Dots run from the side that sent more; width and speed follow the rate. Blue with a TCP tag: the tunnel fell back to TCP/443. An edge between two spokes is a path of their own (PATHS.md), tagged RELAY when it runs through a hub's relay |
| Thin grey dashes | a tunnel that closed within the window; the older, the fainter. "History" switches them off |
| Green or red flash along an edge | the tunnel opened or closed just now (or at the moment the scrubber passed) |

Pointing at a node or tunnel shows its details and dims everything that is not
connected to it; a click keeps the card open, with links to the node and to its
tunnel history. Nodes can be dragged; a dragged node stays where it was put
until a double click or "Re-layout". The kind switches hide nodes, the user
list highlights one person's devices and their tunnels.

## Time

The strip below the graph is the window: the curve is the number of open
tunnels, the ticks are tunnels opening (green) and closing (red). Dragging the
playhead shows the mesh as it was then; "Replay" runs through the window in
about twenty seconds; "Live" returns to now. The arrow keys move the playhead
(Shift: faster), Home and End jump to the ends.

Looking back is reconstructed from what the control plane records: tunnel
events (who, which hub, when, why closed, bytes) and user sessions. It is not
recorded who sent heartbeats when, so past moments show no online ring, and
nodes are the ones approved today: a node revoked since then is missing from
the picture together with its tunnels.

## Where the data comes from

Nothing new on the server. The page polls three admin endpoints every 5 s:
`GET /admin/nodes?state=approved`, `GET /admin/sessions?all=1` and
`GET /admin/tunnels?since=<window start>&limit=5000` (API.md). Hubs report
tunnel events and counters with their flow logs (M3). A hub that dies reports
nothing: its tunnels stay open in the picture until the control plane closes
them after three minutes of silence ("hub stopped reporting", closed at the
last report), or at once when the hub comes back ("hub restarted"). A failover
therefore shows first as the spoke's traffic moving to the other hub's edge and
then as the dead hub's edges turning grey. Rates are
computed in the browser from two successive counter reports of the same tunnel;
for a past moment the card shows the tunnel's lifetime average instead.

With more than 5000 tunnels in the window the oldest are missing from curve and
history; choose a shorter window.

## Code

| File | |
|---|---|
| `web/src/lib/mesh.ts` | the model, no DOM: mesh at a moment (`buildMesh`), rates between reports, activity curve, open/close changes, and the force layout (`step`): charges that repel, tunnels as springs, room kept for labels, hubs with more charge so that two hubs sharing all spokes do not collapse onto each other |
| `web/scripts/mesh-selftest.ts` | tests of the above, part of `make test` |
| `web/src/pages/Mesh.svelte` | drawing and interaction: SVG, one `requestAnimationFrame` loop that runs the layout while it still moves and eases the view box onto the graph |

No graph library: the layout is sixty lines, and a dependency would have to pass
the cooldown and be audited for a page that sees the whole network. Motion stops
under `prefers-reduced-motion`.

`make web-dev` and `http://localhost:5183/mesh?demo` show it without a control
plane: the demo data moves its counters and lets one tunnel flap every 20 s.
