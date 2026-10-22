// One poll loop for every page that keeps a view up to date.
//
// setInterval was wrong in three ways here: it fires again while the last
// round is still running (the Mesh page asks for 5000 tunnels every 5 s), it
// keeps asking while nobody is looking, and it keeps asking at the same rate
// when the control plane is answering 503. This loop runs one round at a
// time, rests while the tab is hidden or the page says so, and backs off
// after a round that failed.
//
// The logic is plain TypeScript so scripts/poll-selftest.ts can drive it with
// a clock of its own; a page reads what it needs from onState.

export type PollState = {
  /** a round is running right now */
  busy: boolean;
  /** when the last round that worked finished (ms) */
  updatedAt?: number;
  /** the last round's error, '' while it works */
  error: string;
  /** rounds that failed in a row */
  failures: number;
};

export type Clock = {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
};

export type PollOptions = {
  /** one round: load what the page shows */
  run: () => Promise<unknown>;
  /** milliseconds between rounds while everything works */
  every: number;
  /** false rests the loop (the "live" checkbox); default: the tab is visible */
  enabled?: () => boolean;
  /** the longest the backoff goes, default a minute */
  maxDelay?: number;
  /** called whenever busy, updatedAt or error changes */
  onState?: (s: PollState) => void;
  clock?: Clock;
};

export type Poller = {
  /** starts the loop with a round now; returns the stop function */
  start(): () => void;
  stop(): void;
  /** runs a round now, or joins the one that is running */
  refresh(): Promise<void>;
  state(): PollState;
};

const realClock: Clock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

const tabVisible = () => typeof document === 'undefined' || !document.hidden;

export function poll(o: PollOptions): Poller {
  const clock = o.clock ?? realClock;
  const enabled = o.enabled ?? tabVisible;
  const maxDelay = Math.max(o.maxDelay ?? 60_000, o.every);
  const state: PollState = { busy: false, error: '', failures: 0 };
  let handle: unknown;
  let inflight: Promise<void> | null = null;
  let stopped = true;
  let onVisible: (() => void) | undefined;

  const report = () => o.onState?.({ ...state });

  // a round that failed is asked again later and later: twice the interval
  // after the first failure, capped, and back to the interval after a round
  // that worked
  const delay = () => Math.min(o.every * 2 ** Math.min(state.failures, 10), maxDelay);

  function schedule() {
    if (stopped) return;
    clock.clearTimeout(handle);
    handle = clock.setTimeout(tick, delay());
  }

  function tick() {
    if (stopped) return;
    if (!enabled()) { schedule(); return; } // rest, but keep the loop alive
    void round();
  }

  function round(): Promise<void> {
    if (inflight) return inflight; // never two at once
    state.busy = true;
    report();
    inflight = Promise.resolve()
      .then(() => o.run())
      .then(() => { state.failures = 0; state.error = ''; state.updatedAt = clock.now(); })
      .catch((e: unknown) => {
        state.failures++;
        state.error = e instanceof Error ? e.message : String(e);
      })
      .then(() => {
        inflight = null;
        state.busy = false;
        report();
        schedule();
      });
    return inflight;
  }

  return {
    start() {
      if (!stopped) return () => this.stop();
      stopped = false;
      if (typeof document !== 'undefined') {
        // back from another tab: show the state as it is now, not in 8 s
        onVisible = () => { if (!stopped && tabVisible()) void round(); };
        document.addEventListener('visibilitychange', onVisible);
      }
      void round();
      return () => this.stop();
    },
    stop() {
      stopped = true;
      clock.clearTimeout(handle);
      if (onVisible && typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', onVisible);
        onVisible = undefined;
      }
    },
    refresh() { return round(); },
    state() { return { ...state }; },
  };
}
