// Thin client for /api/v1/admin. Cookie sessions carry the CSRF header the
// control plane demands; a bearer token (API token, or the bootstrap token
// before the first passkey) is kept in sessionStorage for this tab only.
import type * as T from './types';

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) { super(message); }
}

const TOKEN_KEY = 'bg_token';
export function getToken(): string | null { try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; } }
export function setToken(t: string | null) { try { t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* private mode */ } }

export let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(f: () => void) { onUnauthorized = f; }

export async function api<R = unknown>(method: string, path: string, body?: unknown, opts: { raw?: boolean; silent401?: boolean } = {}): Promise<R> {
  const headers: Record<string, string> = { 'X-Requested-With': 'BoundGate', Accept: 'application/json' };
  const tok = getToken();
  if (tok) headers.Authorization = 'Bearer ' + tok;
  let payload: BodyInit | undefined;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const rsp = await fetch('/api/v1' + path, { method, headers, body: payload, credentials: 'same-origin' });
  if (rsp.status === 204) return undefined as R;
  const text = await rsp.text();
  let data: any = text;
  try { data = text ? JSON.parse(text) : null; } catch { /* not json */ }
  if (!rsp.ok) {
    if (rsp.status === 401 && !opts.silent401) onUnauthorized?.();
    throw new ApiError(rsp.status, (data && data.error) || rsp.statusText || 'request failed', data);
  }
  return data as R;
}

const q = (o: Record<string, string | number | boolean | undefined | null>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? '?' + s : '';
};

export const admin = {
  status: () => api<T.AuthStatus>('GET', '/admin/auth/status', undefined, { silent401: true }),
  logout: () => api('POST', '/admin/auth/logout'),
  overview: () => api<T.Overview>('GET', '/admin/overview'),
  nodes: (state?: string) => api<T.Node[]>('GET', '/admin/nodes' + q({ state })),
  node: (id: string) => api<T.Node>('GET', '/admin/nodes/' + id),
  confirm: (id: string, g: T.Grant) => api<T.Node>('POST', `/admin/nodes/${id}/confirm`, g),
  patchNode: (id: string, g: T.Grant) => api<T.Node>('PATCH', `/admin/nodes/${id}`, g),
  reject: (id: string) => api('POST', `/admin/nodes/${id}/reject`),
  revoke: (id: string) => api('DELETE', `/admin/nodes/${id}`),
  tags: () => api<T.TagOffer>('GET', '/admin/tags'),
  signers: () => api<T.Signer[]>('GET', '/admin/signers'),
  // adding or removing a key only proposes the next signed list (202 + sign command)
  addSigner: (name: string, public_key: string) => api<T.SignerChange>('POST', '/admin/signers', { name, public_key }),
  revokeSigner: (id: string) => api<T.SignerChange>('DELETE', '/admin/signers/' + id),
  signFirstList: () => api<T.SignerChange>('POST', '/admin/signers/change', {}),
  signerSet: () => api<T.SignerSet>('GET', '/admin/signers/set'),
  sessions: (all = false) => api<T.Session[]>('GET', '/admin/sessions' + q({ all: all ? 1 : undefined })),
  revokeSession: (id: string) => api('DELETE', '/admin/sessions/' + id),
  identity: () => api<{ control_pin: string; spki: string }>('GET', '/admin/identity'),
  network: () => api<T.NetworkSettings>('GET', '/admin/settings/network'),
  putNetwork: (n: T.NetworkSettings & { renumber?: boolean }) => api<T.NetworkSettings & { renumbered?: T.Renumbered[] }>('PUT', '/admin/settings/network', n),
  policies: () => api<T.Policy[]>('GET', '/admin/policies'),
  createPolicy: (b: T.PolicyBody) => api<T.Policy>('POST', '/admin/policies', b),
  putPolicy: (id: string, b: T.PolicyBody) => api<T.Policy>('PUT', '/admin/policies/' + id, b),
  deletePolicy: (id: string) => api('DELETE', '/admin/policies/' + id),
  validate: (cedar: string) => api<{ ok: boolean; error?: string }>('POST', '/admin/policies/validate', { cedar }),
  evaluate: (b: T.EvaluateBody) => api<T.Evaluation>('POST', '/admin/acl/evaluate', b),
  tunnels: (o: { node?: string; active?: boolean; since?: string; limit?: number } = {}) => api<T.Tunnel[]>('GET', '/admin/tunnels' + q({ node: o.node, active: o.active ? 1 : undefined, since: o.since, limit: o.limit })),
  flows: (o: Record<string, string | number | undefined>) => api<T.LogEvent[]>('GET', '/admin/flows' + q(o)),
  logs: (o: Record<string, string | number | undefined>) => api<T.LogEvent[]>('GET', '/admin/logs' + q(o)),
  passkeys: () => api<T.Passkey[]>('GET', '/admin/passkeys'),
  approvePasskey: (id: string) => api<T.Passkey>('POST', `/admin/passkeys/${id}/approve`),
  revokePasskey: (id: string) => api('DELETE', '/admin/passkeys/' + id),
  tokens: () => api<T.ApiToken[]>('GET', '/admin/tokens'),
  createToken: (name: string, expires_in: string) => api<T.ApiToken>('POST', '/admin/tokens', { name, expires_in }),
  revokeToken: (id: string) => api('DELETE', '/admin/tokens/' + id),
  snapshot: (node?: string) => api<unknown>('GET', '/admin/snapshot' + q({ node })),
};
