import { admin, setToken, setUnauthorizedHandler, getToken } from './api';
import type { AuthStatus } from './types';

export const auth = $state({ status: null as AuthStatus | null, loading: true, error: '' });

export async function refreshAuth(): Promise<AuthStatus> {
  try {
    const st = await admin.status();
    auth.status = st;
    auth.error = st.error || '';
    return st;
  } catch (e: any) {
    auth.error = e.message || String(e);
    auth.status = { level: 'none', own_passkeys: 0, own_pending: 0, total_passkeys: 0, bootstrap_active: false, oidc_configured: false, passkeys_enabled: false };
    return auth.status;
  } finally {
    auth.loading = false;
  }
}

export async function logout() {
  if (getToken()) setToken(null);
  else await admin.logout().catch(() => {});
  await refreshAuth();
}

export function oidcLoginURL(next = location.pathname + location.search): string {
  return '/api/v1/admin/auth/login?next=' + encodeURIComponent(next || '/');
}

setUnauthorizedHandler(() => {
  if (auth.status && auth.status.level !== 'none') void refreshAuth();
});
