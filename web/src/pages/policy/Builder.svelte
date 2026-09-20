<script lang="ts">
  import type { Node } from '../../lib/types';
  import { condTypes, newCond, condLabel, type Rule, type Cond, type CondType, type Principal, type Resource } from '../../lib/cedar';

  let { rule = $bindable(), nodes, groups, pool }: { rule: Rule; nodes: Node[]; groups: string[]; pool?: string } = $props();
  const roles = ['endpoint', 'subnet-router', 'hub', 'exit-node'];
  const tags = $derived([...new Set(nodes.flatMap((n) => n.tags ?? []))].sort());
  const known = $derived(nodes.filter((n) => n.status === 'approved' || n.status === 'confirmed'));
  const networks = $derived([...new Set([pool, ...nodes.flatMap((n) => n.prefixes.map((p) => p.prefix))].filter(Boolean) as string[])]);

  function setPrincipal(kind: Principal['kind']) {
    switch (kind) {
      case 'any': rule.principal = { kind }; break;
      case 'node': rule.principal = { kind, id: known[0]?.id ?? '' }; break;
      case 'group': rule.principal = { kind, name: groups[0] ?? 'vpn-users' }; break;
      case 'user': rule.principal = { kind, subject: '' }; break;
      case 'role': rule.principal = { kind, role: 'hub' }; break;
      case 'tag': rule.principal = { kind, tag: tags[0] ?? '' }; break;
    }
  }
  function setResource(kind: Resource['kind']) {
    switch (kind) {
      case 'any': rule.resource = { kind }; break;
      case 'network': rule.resource = { kind, prefix: networks[0] ?? '10.0.0.0/8' }; break;
      case 'node': rule.resource = { kind, id: known[0]?.id ?? '' }; break;
      case 'host': rule.resource = { kind, ip: '' }; break;
      case 'tag': rule.resource = { kind, tag: tags[0] ?? '' }; break;
    }
  }
  function add(list: Cond[], type: CondType) { list.push(newCond(type)); }
  function retype(list: Cond[], i: number, type: CondType) { list[i] = newCond(type); }
</script>

{#snippet condRow(list: Cond[], i: number)}
  {@const c = list[i]}
  <div class="cond">
    {#if 'not' in c}
      <button class="neg" class:on={c.not} title="negate" onclick={() => ((list[i] as any).not = !c.not)}>NOT</button>
    {:else}<span></span>{/if}
    <select value={c.type} onchange={(e) => retype(list, i, (e.currentTarget as HTMLSelectElement).value as CondType)}>
      {#each condTypes as t}<option value={t.type}>{t.label}</option>{/each}
    </select>
    <div class="row" style="gap:6px">
      {#if c.type === 'port'}
        <span class="muted small">is</span><input class="grow mono" placeholder="443 or 80, 443" bind:value={c.ports} />
      {:else if c.type === 'proto'}
        <span class="muted small">is</span><select bind:value={c.proto}><option>tcp</option><option>udp</option><option>icmp</option></select>
      {:else if c.type === 'iprange'}
        <span class="muted small">in</span><input class="grow mono" placeholder="10.60.0.0/24 or 10.60.0.11" bind:value={c.cidr} list="bg-networks" />
      {:else if c.type === 'sni' || c.type === 'dns'}
        <select bind:value={c.op}><option value="like">matches</option><option value="notlike">is present but does not match</option><option value="present">is present</option><option value="absent">is absent</option></select>
        {#if c.op === 'like' || c.op === 'notlike'}<input class="grow mono" placeholder="*.internal.example" bind:value={c.pattern} />{/if}
      {:else if c.type === 'kind'}
        <span class="muted small">is</span><select bind:value={c.kind}><option value="interactive">interactive</option><option value="workload">workload</option></select>
      {:else if c.type === 'hardware' || c.type === 'session'}
        <span class="muted small">{condTypes.find((t) => t.type === c.type)?.about}</span>
      {:else if c.type === 'group'}
        <input class="grow" placeholder="group name" bind:value={c.name} list="bg-groups" />
      {:else if c.type === 'role'}
        <select bind:value={c.role}>{#each roles as r}<option>{r}</option>{/each}</select>
      {:else if c.type === 'platform'}
        <select bind:value={c.platform}><option>linux</option><option>darwin</option><option>windows</option></select>
      {/if}
    </div>
    <button class="btn sm ghost" title="remove" onclick={() => list.splice(i, 1)}>✕</button>
  </div>
{/snippet}

<datalist id="bg-networks">{#each networks as n}<option value={n}></option>{/each}</datalist>
<datalist id="bg-groups">{#each groups as g}<option value={g}></option>{/each}</datalist>

<div class="col" style="gap:14px">
  <div class="row">
    <div class="seg">
      <button class="permit" class:active={rule.effect === 'permit'} onclick={() => (rule.effect = 'permit')}>✓ Allow</button>
      <button class="forbid" class:active={rule.effect === 'forbid'} onclick={() => (rule.effect = 'forbid')}>✕ Deny</button>
    </div>
    <span class="hint">{rule.effect === 'permit' ? 'A flow needs at least one matching allow.' : 'A matching deny overrides every allow.'}</span>
  </div>

  <div class="grid cols-2s">
    <div class="card tight col" style="gap:8px">
      <h3>Who (principal)</h3>
      <select value={rule.principal.kind} onchange={(e) => setPrincipal((e.currentTarget as HTMLSelectElement).value as Principal['kind'])}>
        <option value="any">any node</option>
        <option value="group">users in an OIDC group</option>
        <option value="user">one user</option>
        <option value="node">one specific node</option>
        <option value="role">nodes with a role</option>
        <option value="tag">nodes with a tag</option>
      </select>
      {#if rule.principal.kind === 'group'}
        <input placeholder="group name" bind:value={rule.principal.name} list="bg-groups" />
        <span class="hint">True while a member of that group is logged in on the node.</span>
      {:else if rule.principal.kind === 'user'}
        <input placeholder="OIDC subject" bind:value={rule.principal.subject} />
      {:else if rule.principal.kind === 'node'}
        <select bind:value={rule.principal.id}>{#each known as n}<option value={n.id}>{n.name} · {n.overlay_ip}</option>{/each}</select>
      {:else if rule.principal.kind === 'role'}
        <select bind:value={rule.principal.role}>{#each roles as r}<option>{r}</option>{/each}</select>
      {:else if rule.principal.kind === 'tag'}
        <input placeholder="tag" bind:value={rule.principal.tag} list="bg-tags" />
        <span class="hint">Every node that carries this tag (Nodes, "Tags"). Tags are part of the binding an admin key signs, like roles.</span>
      {/if}
    </div>
    <div class="card tight col" style="gap:8px">
      <h3>Where to (resource)</h3>
      <select value={rule.resource.kind} onchange={(e) => setResource((e.currentTarget as HTMLSelectElement).value as Resource['kind'])}>
        <option value="any">anywhere</option>
        <option value="network">a network (announced prefix or the overlay pool)</option>
        <option value="node">a specific node</option>
        <option value="host">one host address</option>
        <option value="tag">nodes with a tag</option>
      </select>
      <datalist id="bg-tags">{#each tags as t}<option value={t}></option>{/each}</datalist>
      {#if rule.resource.kind === 'network'}
        <input class="mono" placeholder="192.168.178.0/24" bind:value={rule.resource.prefix} list="bg-networks" />
        <span class="hint">Matches destinations inside a prefix that a node announces (or the overlay pool).</span>
      {:else if rule.resource.kind === 'node'}
        <select bind:value={rule.resource.id}>{#each known as n}<option value={n.id}>{n.name} · {n.overlay_ip}{n.prefixes.length ? ' + ' + n.prefixes.map((p) => p.prefix).join(', ') : ''}</option>{/each}</select>
        <span class="hint">The node's overlay address and everything behind it.</span>
      {:else if rule.resource.kind === 'host'}
        <input class="mono" placeholder="10.60.0.11" bind:value={rule.resource.ip} />
      {:else if rule.resource.kind === 'tag'}
        <input placeholder="tag" bind:value={rule.resource.tag} list="bg-tags" />
        <span class="hint">The overlay addresses of the nodes with this tag, and everything they announce.</span>
      {/if}
    </div>
  </div>

  <div class="col" style="gap:8px">
    <div class="row between"><h3>Only when all of these hold</h3>
      <select value="" onchange={(e) => { const v = (e.currentTarget as HTMLSelectElement).value as CondType; if (v) add(rule.when, v); (e.currentTarget as HTMLSelectElement).value = ''; }}>
        <option value="">+ add condition…</option>{#each condTypes as t}<option value={t.type}>{t.label}</option>{/each}
      </select>
    </div>
    {#each rule.when as _, i (i)}{@render condRow(rule.when, i)}{:else}<div class="hint">No conditions: applies to every flow between the principal and the resource.</div>{/each}
  </div>

  <div class="col" style="gap:8px">
    <div class="row between"><h3>Except when any of these hold</h3>
      <select value="" onchange={(e) => { const v = (e.currentTarget as HTMLSelectElement).value as CondType; if (v) add(rule.unless, v); (e.currentTarget as HTMLSelectElement).value = ''; }}>
        <option value="">+ add exception…</option>{#each condTypes as t}<option value={t.type}>{t.label}</option>{/each}
      </select>
    </div>
    {#each rule.unless as _, i (i)}{@render condRow(rule.unless, i)}{/each}
  </div>
</div>
