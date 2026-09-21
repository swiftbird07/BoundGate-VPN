// Round-trip check of the policy builder: every condition type generates
// Cedar that parses back into the same model. `npm test` prints the
// generated policies as JSON lines so the lab can validate them with the
// real Cedar parser (deploy/compose/e2e.sh step 12).
import { generate, parse, condTypes, newCond, emptyRule, describe, type Rule, type Cond } from '../src/lib/cedar.ts';

const rules: Rule[] = [];
rules.push(emptyRule());
rules.push({ effect: 'forbid', principal: { kind: 'group', name: 'vpn "users"' }, resource: { kind: 'network', prefix: '192.168.178.0/24' }, when: [], unless: [] });
rules.push({ effect: 'permit', principal: { kind: 'node', id: 'abc123' }, resource: { kind: 'node', id: 'def456' }, when: [], unless: [] });
rules.push({ effect: 'permit', principal: { kind: 'user', subject: 'u1' }, resource: { kind: 'host', ip: '10.60.0.11' }, when: [], unless: [] });
rules.push({ effect: 'permit', principal: { kind: 'role', role: 'subnet-router' }, resource: { kind: 'any' }, when: [], unless: [] });
rules.push({ effect: 'permit', principal: { kind: 'tag', tag: 'priv_client' }, resource: { kind: 'tag', tag: 'server' }, when: [], unless: [] });
for (const t of condTypes) {
  const c = newCond(t.type);
  rules.push({ ...emptyRule(), when: [c] });
  if ('not' in c) rules.push({ ...emptyRule(), when: [{ ...c, not: true } as Cond], unless: [c] });
}
for (const type of ['sni', 'dns'] as const) for (const op of ['like', 'notlike', 'present', 'absent'] as const)
  rules.push({ ...emptyRule(), effect: 'forbid', when: [{ type, op, pattern: op === 'like' || op === 'notlike' ? '*.secret.example' : '' }], unless: [] });
rules.push({ ...emptyRule(), when: [{ type: 'port', ports: '80, 443', not: false }, { type: 'proto', proto: 'tcp', not: false }, { type: 'iprange', cidr: '10.60.0.11', not: true }], unless: [{ type: 'kind', kind: 'workload', not: false }, { type: 'group', name: 'contractors', not: false }] });

let bad = 0;
for (const r of rules) {
  const text = generate(r);
  const back = parse(text);
  if (JSON.stringify(back) !== JSON.stringify(r)) { bad++; console.error('ROUND TRIP FAILED\n', text, '\nwant', JSON.stringify(r), '\ngot ', JSON.stringify(back)); }
  const said = describe(r);
  if (!said || said.includes('undefined')) { bad++; console.error('NO WORDS FOR', text, '\n', said); }
  console.log(JSON.stringify({ cedar: text }));
}
// hand-written policies outside the builder's shape stay raw
for (const raw of ['permit(principal, action, resource) when { principal.name == "x" };', 'permit(principal, action, resource); forbid(principal, action, resource);', 'permit(principal is BoundGate::Node, action, resource);']) {
  if (parse(raw) !== null) { bad++; console.error('should not parse:', raw); }
}
// the docs' examples the builder does cover
for (const ok of ['permit(principal in BoundGate::Group::"vpn-users", action,\n resource in BoundGate::Network::"192.168.178.0/24");', '// comment\nforbid(principal, action, resource) when { resource.ip == ip("192.168.178.99") };', 'forbid(principal, action, resource)\n  when { resource has sni && !(resource.sni like "*.net407.internal") };', 'permit(principal, action, resource) when { principal.hardware_bound && resource.port == 443 && resource.ip.isInRange(ip("10.60.0.0/24")) };']) {
  if (parse(ok) === null) { bad++; console.error('should parse:', ok); }
}
if (bad) { console.error(`${bad} failure(s)`); process.exit(1); }
console.error(`cedar builder: ${rules.length} rules round-trip`);
