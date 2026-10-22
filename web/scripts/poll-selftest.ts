// Self-test of src/lib/poll.ts: node scripts/poll-selftest.ts
import { poll, type Clock, type PollState } from '../src/lib/poll.ts';

let failed = 0;
const ok = (cond: boolean, what: string) => { if (!cond) { failed++; console.error('FAIL:', what); } };

// a clock the test turns by hand
function fakeClock() {
  let t = 1000;
  let next = 1;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const clock: Clock = {
    now: () => t,
    setTimeout: (fn, ms) => { const id = next++; timers.set(id, { at: t + ms, fn }); return id; },
    clearTimeout: (h) => { timers.delete(h as number); },
  };
  // runs every timer that is due; returns how many fired
  const advance = (ms: number) => {
    t += ms;
    let fired = 0;
    for (const [id, timer] of [...timers]) {
      if (timer.at <= t) { timers.delete(id); timer.fn(); fired++; }
    }
    return fired;
  };
  return { clock, advance, pending: () => timers.size, due: () => [...timers.values()].map((x) => x.at - t) };
}

const settle = () => new Promise<void>((r) => setTimeout(r, 0));

// --- one round at a time -------------------------------------------------
{
  const { clock, advance } = fakeClock();
  let runs = 0;
  let release: (() => void) | undefined;
  const p = poll({
    every: 1000, clock, enabled: () => true,
    run: () => { runs++; return new Promise<void>((r) => { release = r; }); },
  });
  p.start();
  await settle();
  ok(runs === 1, 'start runs a round at once');
  advance(5000); // two intervals pass while the first round hangs
  advance(5000);
  await settle();
  ok(runs === 1, 'no second round while one is running: ' + runs);
  const joined = p.refresh();
  await settle();
  ok(runs === 1, 'refresh joins the running round');
  release!();
  await joined;
  ok(p.state().busy === false && p.state().updatedAt === clock.now(), 'a finished round is not busy and stamps the time');
  advance(1000);
  await settle();
  ok(runs === 2, 'the next round comes after the interval: ' + runs);
  p.stop();
  advance(10_000);
  await settle();
  ok(runs === 2, 'stop stops');
}

// --- backoff on errors, reset on success ---------------------------------
{
  const { clock, advance, due } = fakeClock();
  let runs = 0, fail = true;
  const seen: PollState[] = [];
  const p = poll({
    every: 1000, maxDelay: 8000, clock, enabled: () => true,
    onState: (s) => seen.push(s),
    run: async () => { runs++; if (fail) throw new Error('503 busy'); },
  });
  p.start();
  await settle();
  ok(p.state().failures === 1 && p.state().error === '503 busy', 'a failed round is counted with its message');
  ok(due()[0] === 2000, 'the first failure doubles the interval: ' + due()[0]);
  for (let i = 0; i < 6; i++) { advance(8000); await settle(); }
  ok(due()[0] === 8000, 'the backoff stops at maxDelay: ' + due()[0]);
  ok(p.state().failures === 7, 'every failure counts: ' + p.state().failures);
  fail = false;
  advance(8000);
  await settle();
  ok(p.state().failures === 0 && p.state().error === '' && due()[0] === 1000, 'one round that works resets the backoff');
  ok(seen.some((s) => s.busy) && seen.some((s) => !s.busy), 'onState reports busy and idle');
  p.stop();
  ok(runs === 8, 'rounds: ' + runs);
}

// --- resting: disabled does not ask, but keeps the loop alive ------------
{
  const { clock, advance, pending } = fakeClock();
  let runs = 0, live = false;
  const p = poll({ every: 1000, clock, enabled: () => live, run: async () => { runs++; } });
  p.start();
  await settle();
  ok(runs === 1, 'the first round runs whatever enabled says (the page wants its data)');
  advance(1000); await settle();
  advance(1000); await settle();
  ok(runs === 1, 'while resting nothing is asked: ' + runs);
  ok(pending() === 1, 'the loop is still scheduled');
  live = true;
  advance(1000); await settle();
  ok(runs === 2, 'it picks up again without a restart');
  p.stop();
}

if (failed) { console.error(`${failed} check(s) failed`); process.exit(1); }
console.log('poll self-test: ok');
