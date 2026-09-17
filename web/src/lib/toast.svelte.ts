export interface Toast { id: number; kind: 'ok' | 'bad' | 'info'; text: string }
export const toasts = $state<Toast[]>([]);
let seq = 0;
export function toast(text: string, kind: Toast['kind'] = 'info', ms = 4200) {
  const id = ++seq;
  toasts.push({ id, kind, text });
  setTimeout(() => { const i = toasts.findIndex((t) => t.id === id); if (i >= 0) toasts.splice(i, 1); }, ms);
}
export function fail(e: unknown) { toast(e instanceof Error ? e.message : String(e), 'bad', 6000); }
