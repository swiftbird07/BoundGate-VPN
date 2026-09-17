export function ago(iso?: string | null): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return iso;
  const d = Math.round((Date.now() - t) / 1000);
  const abs = Math.abs(d), sfx = d < 0 ? 'from now' : 'ago';
  if (abs < 5) return 'just now';
  if (abs < 60) return `${abs} s ${sfx}`;
  if (abs < 3600) return `${Math.round(abs / 60)} min ${sfx}`;
  if (abs < 86400) return `${Math.round(abs / 3600)} h ${sfx}`;
  return `${Math.round(abs / 86400)} d ${sfx}`;
}
export function when(iso?: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
export function bytes(n?: number): string {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}
export function duration(from: string, to?: string | null): string {
  const a = new Date(from).getTime(), b = to ? new Date(to).getTime() : Date.now();
  const s = Math.max(0, Math.round((b - a) / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
}
export function short(id: string, n = 10): string { return id.length > n ? id.slice(0, n) + '…' : id; }
export async function copy(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}
export function statusTone(s: string): 'ok' | 'warn' | 'bad' | 'info' | '' {
  switch (s) {
    case 'approved': case 'active': case 'allow': case 'done': return 'ok';
    case 'pending': case 'oidc_only': return 'warn';
    case 'confirmed': return 'info';
    case 'revoked': case 'deny': case 'failed': case 'ended': return 'bad';
    default: return '';
  }
}
