// The policy builder's model and its two directions: model → Cedar text and
// (for policies the builder wrote, or simple hand-written ones) Cedar → model.
// Anything the parser does not understand stays a raw Cedar policy.

export type Effect = 'permit' | 'forbid';
export type Principal =
  | { kind: 'any' }
  | { kind: 'node'; id: string }
  | { kind: 'group'; name: string }
  | { kind: 'user'; subject: string }
  | { kind: 'role'; role: string }
  | { kind: 'tag'; tag: string };
export type Resource =
  | { kind: 'any' }
  | { kind: 'tag'; tag: string }
  | { kind: 'network'; prefix: string }
  | { kind: 'node'; id: string }
  | { kind: 'host'; ip: string }
  | { kind: 'list'; list: string };
export type NameOp = 'like' | 'notlike' | 'present' | 'absent';
export type Cond =
  | { type: 'port'; ports: string; not: boolean }
  | { type: 'proto'; proto: string; not: boolean }
  | { type: 'iprange'; cidr: string; not: boolean }
  | { type: 'sni'; op: NameOp; pattern: string }
  | { type: 'dns'; op: NameOp; pattern: string }
  | { type: 'kind'; kind: string; not: boolean }
  | { type: 'hardware'; not: boolean }
  | { type: 'session'; not: boolean }
  | { type: 'group'; name: string; not: boolean }
  | { type: 'role'; role: string; not: boolean }
  | { type: 'platform'; platform: string; not: boolean }
  | { type: 'list'; list: string; not: boolean };
export type CondType = Cond['type'];
export interface Rule { effect: Effect; principal: Principal; resource: Resource; when: Cond[]; unless: Cond[] }

export const condTypes: { type: CondType; label: string; about: string }[] = [
  { type: 'port', label: 'Destination port', about: 'one port or a comma-separated list' },
  { type: 'proto', label: 'Protocol', about: 'tcp, udp or icmp' },
  { type: 'iprange', label: 'Destination address', about: 'an address or a CIDR range' },
  { type: 'sni', label: 'TLS server name (SNI)', about: 'seen in the ClientHello; * matches any characters' },
  { type: 'dns', label: 'DNS query name', about: 'the name a DNS query asks for' },
  { type: 'kind', label: 'Node kind', about: 'interactive (user logs in) or workload' },
  { type: 'hardware', label: 'Hardware-bound key', about: 'the node key lives in a TPM or Secure Enclave' },
  { type: 'session', label: 'User session present', about: 'a user is logged in on the node' },
  { type: 'group', label: 'User in group', about: 'an OIDC group of the logged-in user' },
  { type: 'role', label: 'Node has role', about: 'endpoint, subnet-router, hub or exit-node' },
  { type: 'platform', label: 'Node platform', about: 'linux, darwin, windows' },
  { type: 'list', label: 'Destination in a list', about: 'a list of addresses, names, or both at once (Lists)' },
];

export function newCond(type: CondType): Cond {
  switch (type) {
    case 'port': return { type, ports: '443', not: false };
    case 'proto': return { type, proto: 'tcp', not: false };
    case 'iprange': return { type, cidr: '10.0.0.0/8', not: false };
    case 'sni': return { type, op: 'like', pattern: '*.example.com' };
    case 'dns': return { type, op: 'like', pattern: '*.example.com' };
    case 'kind': return { type, kind: 'workload', not: false };
    case 'hardware': return { type, not: false };
    case 'session': return { type, not: false };
    case 'group': return { type, name: 'vpn-users', not: false };
    case 'role': return { type, role: 'hub', not: false };
    case 'platform': return { type, platform: 'linux', not: false };
    case 'list': return { type, list: '', not: false };
  }
}

export function emptyRule(): Rule {
  return { effect: 'permit', principal: { kind: 'any' }, resource: { kind: 'any' }, when: [], unless: [] };
}

const str = (s: string) => JSON.stringify(s);

function principalText(p: Principal): string {
  switch (p.kind) {
    case 'any': return 'principal';
    case 'node': return `principal == BoundGate::Node::${str(p.id)}`;
    case 'group': return `principal in BoundGate::Group::${str(p.name)}`;
    case 'user': return `principal in BoundGate::User::${str(p.subject)}`;
    case 'role': return `principal in BoundGate::Role::${str(p.role)}`;
    case 'tag': return `principal in BoundGate::Tag::${str(p.tag)}`;
  }
}
function resourceText(r: Resource): string {
  switch (r.kind) {
    case 'any': return 'resource';
    case 'network': return `resource in BoundGate::Network::${str(r.prefix)}`;
    case 'node': return `resource in BoundGate::Node::${str(r.id)}`;
    case 'host': return `resource == BoundGate::Host::${str(r.ip)}`;
    case 'tag': return `resource in BoundGate::Tag::${str(r.tag)}`;
    case 'list': return `resource in BoundGate::List::${str(r.list)}`;
  }
}

function nameCond(field: string, has: string, c: { op: NameOp; pattern: string }): string {
  switch (c.op) {
    case 'like': return `(${has} && ${field} like ${str(c.pattern)})`;
    case 'notlike': return `(${has} && !(${field} like ${str(c.pattern)}))`;
    case 'present': return has;
    case 'absent': return `!(${has})`;
  }
}

export function condText(c: Cond): string {
  let t: string;
  let not = 'not' in c ? c.not : false;
  switch (c.type) {
    case 'port': {
      const ports = c.ports.split(',').map((s) => s.trim()).filter(Boolean);
      t = ports.length === 1 ? `resource.port == ${Number(ports[0]) || 0}` : `[${ports.map((p) => Number(p) || 0).join(', ')}].contains(resource.port)`;
      break;
    }
    case 'proto': t = `resource.protocol == ${str(c.proto)}`; break;
    case 'iprange': t = c.cidr.includes('/') ? `resource.ip.isInRange(ip(${str(c.cidr)}))` : `resource.ip == ip(${str(c.cidr)})`; break;
    case 'sni': t = nameCond('resource.sni', 'resource has sni', c); break;
    case 'dns': t = nameCond('context.dns_name', 'context has dns_name', c); break;
    case 'kind': t = `principal.kind == ${str(c.kind)}`; break;
    case 'hardware': t = 'principal.hardware_bound'; break;
    case 'session': t = 'principal.has_session'; break;
    case 'group': t = `(context has user && context.user.groups.contains(${str(c.name)}))`; break;
    case 'role': t = `principal.roles.contains(${str(c.role)})`; break;
    case 'platform': t = `principal.platform == ${str(c.platform)}`; break;
    case 'list': t = `resource in BoundGate::List::${str(c.list)}`; break;
  }
  return not ? `!(${t})` : t;
}

export function generate(r: Rule): string {
  let out = `${r.effect}(\n  ${principalText(r.principal)},\n  action,\n  ${resourceText(r.resource)}\n)`;
  if (r.when.length) out += `\nwhen { ${r.when.map(condText).join(' && ')} }`;
  if (r.unless.length) out += `\nunless { ${r.unless.map(condText).join(' || ')} }`;
  return out + ';\n';
}

// --- parsing -----------------------------------------------------------------

const ENT = (t: string) => new RegExp(`^${t}\\s*(==|in)\\s*BoundGate::(\\w+)::"((?:[^"\\\\]|\\\\.)*)"$`);

function unstr(s: string): string { try { return JSON.parse('"' + s + '"'); } catch { return s; } }

function splitTop(s: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0, inStr = false, cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inStr) { cur += ch; if (ch === '\\') { cur += s[++i] ?? ''; } else if (ch === '"') inStr = false; continue; }
    if (ch === '"') { inStr = true; cur += ch; continue; }
    if (ch === '(' || ch === '[') depth++;
    if (ch === ')' || ch === ']') depth--;
    if (depth === 0 && s.startsWith(sep, i)) { out.push(cur); cur = ''; i += sep.length - 1; continue; }
    cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim());
}

function stripParens(s: string): string {
  s = s.trim();
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0, ok = true;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '(') depth++;
      else if (s[i] === ')') { depth--; if (depth === 0 && i < s.length - 1) { ok = false; break; } }
    }
    if (!ok) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

function parseAtom(raw: string): Cond | null {
  let s = stripParens(raw);
  let not = false;
  if (s.startsWith('!')) { not = true; s = stripParens(s.slice(1)); }
  let m: RegExpMatchArray | null;
  if ((m = s.match(/^resource\.port\s*==\s*(\d+)$/))) return { type: 'port', ports: m[1], not };
  if ((m = s.match(/^\[([\d,\s]+)\]\.contains\(resource\.port\)$/))) return { type: 'port', ports: m[1].split(',').map((x) => x.trim()).join(', '), not };
  if ((m = s.match(/^resource\.protocol\s*==\s*"(\w+)"$/))) return { type: 'proto', proto: m[1], not };
  if ((m = s.match(/^resource\.ip\.isInRange\(ip\("([^"]+)"\)\)$/))) return { type: 'iprange', cidr: m[1], not };
  if ((m = s.match(/^resource\.ip\s*==\s*ip\("([^"]+)"\)$/))) return { type: 'iprange', cidr: m[1], not };
  if ((m = s.match(/^principal\.kind\s*==\s*"(\w+)"$/))) return { type: 'kind', kind: m[1], not };
  if (s === 'principal.hardware_bound') return { type: 'hardware', not };
  if (s === 'principal.has_session') return { type: 'session', not };
  if ((m = s.match(/^principal\.roles\.contains\("([\w-]+)"\)$/))) return { type: 'role', role: m[1], not };
  if ((m = s.match(/^principal\.platform\s*==\s*"(\w+)"$/))) return { type: 'platform', platform: m[1], not };
  if ((m = s.match(/^resource in BoundGate::List::"((?:[^"\\]|\\.)*)"$/))) return { type: 'list', list: unstr(m[1]), not };
  if ((m = s.match(/^context has user\s*&&\s*context\.user\.groups\.contains\("((?:[^"\\]|\\.)*)"\)$/))) return { type: 'group', name: unstr(m[1]), not };
  for (const [type, field, has] of [['sni', 'resource.sni', 'resource has sni'], ['dns', 'context.dns_name', 'context has dns_name']] as const) {
    if (s === has) return { type, op: not ? 'absent' : 'present', pattern: '' };
    const esc = field.replace(/\./g, '\\.');
    if (!not && (m = s.match(new RegExp(`^${has}\\s*&&\\s*${esc}\\s+like\\s+"((?:[^"\\\\]|\\\\.)*)"$`)))) return { type, op: 'like', pattern: unstr(m[1]) };
    if (!not && (m = s.match(new RegExp(`^${has}\\s*&&\\s*!\\(\\s*${esc}\\s+like\\s+"((?:[^"\\\\]|\\\\.)*)"\\s*\\)$`)))) return { type, op: 'notlike', pattern: unstr(m[1]) };
  }
  return null;
}

/** parse returns the builder model for a single policy the builder can
 *  represent, else null. */
export function parse(cedar: string): Rule | null {
  const text = cedar.replace(/\/\/[^\n]*/g, '').replace(/\s+/g, ' ').trim();
  const stmts = splitTop(text, ';').filter(Boolean);
  if (stmts.length !== 1) return null;
  const m = stmts[0].match(/^(permit|forbid)\s*\((.*)\)\s*(.*)$/s);
  if (!m) return null;
  // the head ends at the first ")" at depth 0
  let depth = 0, headEnd = -1;
  const body = stmts[0];
  for (let i = body.indexOf('('); i < body.length; i++) {
    if (body[i] === '(') depth++;
    else if (body[i] === ')') { depth--; if (depth === 0) { headEnd = i; break; } }
  }
  if (headEnd < 0) return null;
  const head = body.slice(body.indexOf('(') + 1, headEnd);
  const tail = body.slice(headEnd + 1).trim();
  const parts = splitTop(head, ',');
  if (parts.length !== 3) return null;
  const [pp, ap, rp] = parts;
  if (!/^action(\s*==\s*BoundGate::Action::"connect")?$/.test(ap)) return null;
  let principal: Principal;
  if (pp === 'principal') principal = { kind: 'any' };
  else {
    const e = pp.match(ENT('principal'));
    if (!e) return null;
    const [, op, ty, id] = e;
    if (op === '==' && ty === 'Node') principal = { kind: 'node', id: unstr(id) };
    else if (op === 'in' && ty === 'Group') principal = { kind: 'group', name: unstr(id) };
    else if (op === 'in' && ty === 'User') principal = { kind: 'user', subject: unstr(id) };
    else if (op === 'in' && ty === 'Role') principal = { kind: 'role', role: unstr(id) };
    else if (op === 'in' && ty === 'Tag') principal = { kind: 'tag', tag: unstr(id) };
    else return null;
  }
  let resource: Resource;
  if (rp === 'resource') resource = { kind: 'any' };
  else {
    const e = rp.match(ENT('resource'));
    if (!e) return null;
    const [, op, ty, id] = e;
    if (op === 'in' && ty === 'Network') resource = { kind: 'network', prefix: unstr(id) };
    else if (op === 'in' && ty === 'Node') resource = { kind: 'node', id: unstr(id) };
    else if (op === '==' && ty === 'Host') resource = { kind: 'host', ip: unstr(id) };
    else if (op === 'in' && ty === 'Tag') resource = { kind: 'tag', tag: unstr(id) };
    else if (op === 'in' && ty === 'List') resource = { kind: 'list', list: unstr(id) };
    else return null;
  }
  const rule: Rule = { effect: m[1] as Effect, principal, resource, when: [], unless: [] };
  let rest = tail;
  const seen = new Set<string>();
  while (rest) {
    const b = rest.match(/^(when|unless)\s*\{/);
    if (!b) return null;
    let d = 0, end = -1;
    for (let i = rest.indexOf('{'); i < rest.length; i++) {
      if (rest[i] === '{') d++;
      else if (rest[i] === '}') { d--; if (d === 0) { end = i; break; } }
    }
    if (end < 0 || seen.has(b[1])) return null;
    seen.add(b[1]);
    const inner = rest.slice(rest.indexOf('{') + 1, end).trim();
    rest = rest.slice(end + 1).trim();
    if (!inner) continue;
    let atoms = splitTop(inner, b[1] === 'when' ? '&&' : '||');
    if (b[1] === 'when') {
      // hand-written guards without parentheses: `resource has sni && resource.sni like "…"`
      const merged: string[] = [];
      for (let i = 0; i < atoms.length; i++) {
        const guard = atoms[i] === 'resource has sni' ? 'resource.sni' : atoms[i] === 'context has dns_name' ? 'context.dns_name' : '';
        if (guard && i + 1 < atoms.length && stripParens(atoms[i + 1].replace(/^!/, '')).startsWith(guard + ' ')) { merged.push(`${atoms[i]} && ${atoms[i + 1]}`); i++; }
        else merged.push(atoms[i]);
      }
      atoms = merged;
    }
    for (const a of atoms) {
      const c = parseAtom(a);
      if (!c) return null;
      (b[1] === 'when' ? rule.when : rule.unless).push(c);
    }
  }
  return rule;
}

/** describe renders a rule as one English sentence for lists and previews. */
export function describe(r: Rule): string {
  const who = ((): string => {
    switch (r.principal.kind) {
      case 'any': return 'any node';
      case 'node': return `node ${r.principal.id}`;
      case 'group': return `users in group “${r.principal.name}”`;
      case 'user': return `user ${r.principal.subject}`;
      case 'role': return `nodes with role ${r.principal.role}`;
      case 'tag': return `nodes tagged “${r.principal.tag}”`;
    }
  })();
  const where = ((): string => {
    switch (r.resource.kind) {
      case 'any': return 'anything';
      case 'network': return `network ${r.resource.prefix}`;
      case 'node': return `node ${r.resource.id}`;
      case 'host': return `host ${r.resource.ip}`;
      case 'tag': return `nodes tagged “${r.resource.tag}”`;
      case 'list': return `what is in list “${r.resource.list}”`;
    }
  })();
  let s = `${r.effect === 'permit' ? 'Allow' : 'Deny'} ${who} → ${where}`;
  if (r.when.length) s += ` when ${r.when.map(condLabel).join(' and ')}`;
  if (r.unless.length) s += ` unless ${r.unless.map(condLabel).join(' or ')}`;
  return s;
}

export function condLabel(c: Cond): string {
  const n = 'not' in c && c.not ? 'not ' : '';
  switch (c.type) {
    case 'port': return `${n}port ${c.ports}`;
    case 'proto': return `${n}${c.proto}`;
    case 'iprange': return `${n}to ${c.cidr}`;
    case 'sni': return c.op === 'present' ? 'TLS with SNI' : c.op === 'absent' ? 'no SNI' : `SNI ${c.op === 'notlike' ? 'not ' : ''}like ${c.pattern}`;
    case 'dns': return c.op === 'present' ? 'DNS query' : c.op === 'absent' ? 'not a DNS query' : `DNS name ${c.op === 'notlike' ? 'not ' : ''}like ${c.pattern}`;
    case 'kind': return `${n}${c.kind} node`;
    case 'hardware': return `${n}hardware-bound`;
    case 'session': return `${n}logged in`;
    case 'group': return `${n}user in ${c.name}`;
    case 'role': return `${n}role ${c.role}`;
    case 'platform': return `${n}on ${c.platform}`;
    case 'list': return `${n}in list ${c.list}`;
  }
}

/** highlight wraps Cedar keywords and strings for the preview (HTML). */
export function highlight(cedar: string): string {
  const esc = cedar.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  return esc
    .replace(/"(?:[^"\\]|\\.)*"/g, (m) => `<span class="str">${m}</span>`)
    .replace(/\b(permit|forbid)\b/g, (m) => `<span class="kw ${m}">${m}</span>`)
    .replace(/\b(when|unless|principal|action|resource|context|in|has|like|is)\b/g, '<span class="kw">$1</span>')
    .replace(/BoundGate::\w+/g, '<span class="ent">$&</span>');
}
