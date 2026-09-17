<script lang="ts">
  import { admin } from '../../lib/api';
  import type { Node, Evaluation, EvaluateBody } from '../../lib/types';

  let { nodes, draft, valid, dirty }: { nodes: Node[]; draft: { id: string; name: string; cedar: string }; valid: boolean; dirty: boolean } = $props();
  const candidates = $derived(nodes.filter((n) => n.status === 'approved'));
  let node = $state('');
  let dst = $state('');
  let port = $state(443);
  let proto = $state('tcp');
  let sni = $state('');
  let dns = $state('');
  let enforcer = $state('');
  let draftOnly = $state(false);
  let withDraft = $state<Evaluation | null>(null);
  let saved = $state<Evaluation | null>(null);
  let error = $state('');
  let running = $state(false);

  $effect(() => { if (!node && candidates.length) node = (candidates.find((n) => n.kind === 'interactive') ?? candidates[0]).id; });
  $effect(() => {
    if (!dst && nodes.length) {
      const r = nodes.find((n) => n.prefixes.length);
      if (r) { const p = r.prefixes[0].prefix.split('/')[0].split('.'); p[3] = '10'; dst = p.join('.'); }
      else if (candidates[0]?.overlay_ip) dst = candidates[0].overlay_ip;
    }
  });

  let t: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    // re-run whenever an input or the draft changes
    const body: EvaluateBody = { node, dst, port: Number(port) || 0, proto, sni: sni || undefined, dns_name: dns || undefined, enforcer: enforcer || undefined };
    const d = { ...draft };
    const v = valid, only = draftOnly;
    clearTimeout(t);
    if (!node || !dst) return;
    t = setTimeout(async () => {
      running = true; error = '';
      try {
        const [a, b] = await Promise.all([
          v ? admin.evaluate({ ...body, draft: d, draft_only: only }) : Promise.resolve(null),
          admin.evaluate(body),
        ]);
        withDraft = a; saved = b;
      } catch (e: any) { error = e.message; } finally { running = false; }
    }, 300);
  });
</script>

<div class="card col" style="gap:12px; position:sticky; top:16px">
  <div class="row between"><h2>Sanity check</h2>{#if running}<span class="spinner"></span>{/if}</div>
  <p class="small muted">Evaluates a sample connection with the real engine against the current registry (sessions included) and <b>this editor's unsaved rule</b>.</p>
  <div class="grid cols-2">
    <label class="field">From node <select bind:value={node}>{#each candidates as n}<option value={n.id}>{n.name}</option>{/each}</select></label>
    <label class="field">To address <input class="mono" bind:value={dst} placeholder="192.168.178.10" /></label>
    <label class="field">Port <input type="number" min="0" max="65535" bind:value={port} /></label>
    <label class="field">Protocol <select bind:value={proto}><option>tcp</option><option>udp</option><option>icmp</option></select></label>
    <label class="field">TLS server name <input bind:value={sni} placeholder="optional" /></label>
    <label class="field">DNS query name <input bind:value={dns} placeholder="optional" /></label>
  </div>
  <details><summary class="small muted" style="cursor:pointer">Advanced</summary>
    <div class="col" style="margin-top:8px">
      <label class="field">Enforcing node (its scoped policy view) <select bind:value={enforcer}><option value="">global view (all enabled policies)</option>{#each candidates as n}<option value={n.id}>{n.name}</option>{/each}</select></label>
      <label class="check small"><input type="checkbox" bind:checked={draftOnly} /> evaluate the draft alone (ignore stored policies)</label>
    </div>
  </details>

  {#if error}<div class="error small">{error}</div>{/if}
  {#if !valid}
    <div class="verdict"><span>—</span><span class="muted" style="font-weight:500; font-size:14px">Fix the Cedar first; the draft cannot be evaluated.</span></div>
  {:else if withDraft}
    <div class="verdict {withDraft.allow ? 'allow' : 'deny'}">
      <span class="big">{withDraft.allow ? 'ALLOW' : 'DENY'}</span>
      <span class="small" style="font-weight:500">with your {dirty ? 'unsaved draft' : 'policy'}{#if saved && saved.allow !== withDraft.allow} · <b>changes the outcome</b> (currently {saved.allow ? 'allowed' : 'denied'}){:else if saved} · same as today{/if}</span>
    </div>
    <dl class="kv small">
      <dt>Principal</dt><dd>{nodes.find((n) => n.id === withDraft?.principal)?.name ?? withDraft.principal}{#if withDraft.user} · user <b>{withDraft.user}</b> in {withDraft.groups?.join(', ') || 'no groups'}{:else} · <span class="warn" style="color:var(--warn)">no user session</span>{/if}</dd>
      <dt>Destination</dt><dd>{dst}:{port}/{proto}{#if withDraft.owner_name} · owned by <b>{withDraft.owner_name}</b>{:else} · not inside any announced prefix{/if}</dd>
      <dt>Decided by</dt><dd>{#if withDraft.policies.length}{#each withDraft.policies as p}<span class="chip" class:mono={false}>{p}</span> {/each}{:else}<span class="muted">no policy matched → default deny</span>{/if}</dd>
      <dt>Policies</dt><dd>{withDraft.policy_count} evaluated{#if withDraft.policy_errors?.length} · <span class="error">{withDraft.policy_errors.length} failed to compile</span>{/if}</dd>
      {#if withDraft.errors?.length}<dt>Errors</dt><dd class="error">{withDraft.errors.join('; ')}</dd>{/if}
    </dl>
    {#if withDraft.errors?.length}
      <div class="hint">An evaluation error means a policy touched an attribute the flow does not have (for example <code>resource.sni</code> on a plain TCP flow). Guard it with “is present” or the builder's SNI/DNS conditions.</div>
    {/if}
  {/if}
</div>
