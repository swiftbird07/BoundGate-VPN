// Browser side of the passkey ceremonies. The control plane speaks the
// WebAuthn JSON forms; only the byte fields need base64url conversion.
import { api } from './api';

const b64u = {
  dec(s: string): ArrayBuffer {
    const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  },
  enc(b: ArrayBuffer): string {
    let s = '';
    for (const c of new Uint8Array(b)) s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

export async function registerPasskey(label: string, bootstrapToken: string): Promise<{ id: string; status: string; level: string; mode: string }> {
  const begin = await api<{ mode: string; options: { publicKey: any } }>('POST', '/admin/auth/passkey/register/begin', { label, bootstrap_token: bootstrapToken });
  const pk = begin.options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map((c: any) => ({ ...c, id: b64u.dec(c.id) }));
  const cred = (await navigator.credentials.create({ publicKey: pk })) as PublicKeyCredential | null;
  if (!cred) throw new Error('the browser returned no credential');
  const r = cred.response as AuthenticatorAttestationResponse;
  const body = {
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    response: { attestationObject: b64u.enc(r.attestationObject), clientDataJSON: b64u.enc(r.clientDataJSON), transports: r.getTransports ? r.getTransports() : [] },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  const fin = await api<{ id: string; status: string; level: string }>('POST', '/admin/auth/passkey/register/finish', body);
  return { ...fin, mode: begin.mode };
}

export async function loginPasskey(): Promise<void> {
  const begin = await api<{ options: { publicKey: any } }>('POST', '/admin/auth/passkey/login/begin', {});
  const pk = begin.options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials || []).map((c: any) => ({ ...c, id: b64u.dec(c.id) }));
  const cred = (await navigator.credentials.get({ publicKey: pk })) as PublicKeyCredential | null;
  if (!cred) throw new Error('the browser returned no assertion');
  const r = cred.response as AuthenticatorAssertionResponse;
  const body = {
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    response: { authenticatorData: b64u.enc(r.authenticatorData), clientDataJSON: b64u.enc(r.clientDataJSON), signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  await api('POST', '/admin/auth/passkey/login/finish', body);
}
