/**
 * Webhook burst load test against the real built service (dist/main.js) as a child
 * process, a fake api (HMAC verified, configurable latency/outage) and real Redis.
 *
 *   npm run build && REDIS_URL=redis://127.0.0.1:6379/7 npx tsx scripts/loadtest.ts [scenario...]
 *
 * Scenarios: steady (5k webhooks/min for 30 s), burst (max throughput), api-outage
 * (api down mid-burst, then back), redis-outage (Redis unreachable), shutdown (SIGTERM
 * mid-burst). Every scenario acts like a store: non-2xx answers are redelivered with
 * backoff until 2xx, and a share of 2xx'd events is redelivered as duplicates. At the end
 * it checks that every event reached the api (no loss) and counts duplicate api calls.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer, Agent, request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { stripeSignatureHeader } from '../src/stripe/signature.js';
import { makePki } from '../test/helpers/certs.js';
import { verifyContractSignature } from '../test/helpers/fakeApi.js';

const SECRET = 'billing-service-secret-for-loadtest';
const STRIPE = 'whsec_loadtest_secret';
const USER = '6f1c2d3e-4b5a-4c6d-8e7f-901a2b3c4d5e';
const REDIS_URL = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379/7';

// ---------- fake api ----------
interface FakeApiState {
  latencyMs: number;
  down: boolean;
  applied: Map<string, number>;
  requests: number;
  badSig: number;
  inFlight: number;
  peakInFlight: number;
}
async function startApi() {
  const st: FakeApiState = { latencyMs: 15, down: false, applied: new Map(), requests: 0, badSig: 0, inFlight: 0, peakInFlight: 0 };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', async () => {
      st.requests++;
      st.inFlight++;
      st.peakInFlight = Math.max(st.peakInFlight, st.inFlight);
      try {
        if (req.url?.startsWith('/.well-known')) {
          res.writeHead(200).end('{"keys":[]}');
          return;
        }
        const body = Buffer.concat(chunks).toString('utf8');
        await sleep(st.latencyMs * (0.5 + Math.random()));
        if (st.down) {
          res.writeHead(503, { 'Content-Type': 'application/json' }).end('{"error":{"code":"internal","message":"down"}}');
          return;
        }
        if (!verifyContractSignature(SECRET, { method: req.method ?? '', path: req.url ?? '', headers: req.headers, body })) {
          st.badSig++;
          res.writeHead(401).end();
          return;
        }
        const id = (JSON.parse(body) as { event_id: string }).event_id;
        const n = st.applied.get(id) ?? 0;
        st.applied.set(id, n + 1);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(n === 0 ? { applied: true } : { applied: false, reason: 'duplicate' }));
      } finally {
        st.inFlight--;
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { st, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => server.close() };
}

// ---------- service under test ----------
async function startService(apiUrl: string, port: number, env: Record<string, string> = {}) {
  const pki = await makePki();
  const rootPath = join(tmpdir(), `loadtest-root-${process.pid}.pem`);
  writeFileSync(rootPath, pki.rootPem);
  const child = spawn(process.execPath, ['dist/main.js'], {
    env: {
      PATH: process.env.PATH ?? '',
      API_URL: apiUrl, BILLING_SERVICE_SECRET: SECRET, STRIPE_WEBHOOK_SECRET: STRIPE,
      APPLE_ROOT_CA_PATH: rootPath, GOOGLE_PUSH_TOKEN: 'google-push-token-0123456789',
      REDIS_URL, REDIS_KEY_PREFIX: `loadtest:${Date.now()}:`, PORT: String(port), HOST: '127.0.0.1',
      LOG_LEVEL: process.env.LOG_LEVEL ?? 'warn', ...(process.env.SVC_NODE_OPTIONS ? { NODE_OPTIONS: process.env.SVC_NODE_OPTIONS } : {}), ...env,
    },
    stdio: ['ignore', process.env.SVC_STDOUT ? 'inherit' : 'ignore', 'pipe'],
  });
  let stderr = '';
  child.stderr!.on('data', (d: Buffer) => (stderr += d.toString()));
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (r.ok) return { child, stderr: () => stderr };
    } catch { /* not up yet */ }
    await sleep(50);
  }
  throw new Error(`service did not start: ${stderr}`);
}

function cpuSeconds(child: ChildProcess): number {
  try {
    const f = readFileSync(`/proc/${child.pid}/stat`, 'utf8').split(') ')[1]!.split(' ');
    return (Number(f[11]) + Number(f[12])) / 100; // utime + stime, in clock ticks (100 Hz)
  } catch {
    return NaN;
  }
}

function rssMb(child: ChildProcess): number {
  try {
    const m = /VmRSS:\s+(\d+) kB/.exec(readFileSync(`/proc/${child.pid}/status`, 'utf8'));
    return m ? Number(m[1]) / 1024 : NaN;
  } catch {
    return NaN;
  }
}

// ---------- store simulator ----------
const agent = new Agent({ keepAlive: true, maxSockets: 512 });
function post(port: number, payload: string): Promise<{ status: number; ms: number }> {
  const t0 = performance.now();
  const sig = stripeSignatureHeader(payload, STRIPE, Math.floor(Date.now() / 1000));
  return new Promise((resolve) => {
    const req = request({
      host: '127.0.0.1', port, path: '/billing/stripe/webhook', method: 'POST', agent,
      headers: { 'content-type': 'application/json', 'stripe-signature': sig, 'content-length': Buffer.byteLength(payload) },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode ?? 0, ms: performance.now() - t0 }));
    });
    req.on('error', () => resolve({ status: 0, ms: performance.now() - t0 }));
    req.setTimeout(30_000, () => req.destroy());
    req.end(payload);
  });
}

const stripeEvent = (id: string, created: number) => JSON.stringify({
  id, type: 'customer.subscription.updated', created,
  data: { object: {
    object: 'subscription', id: `sub_${id}`, status: 'active', metadata: { user_id: USER },
    items: { data: [{ current_period_end: created + 30 * 86400, price: { id: 'price_1', lookup_key: 'premium_monthly' } }] },
  } },
});

interface RunStats {
  latencies: number[];
  statuses: Map<number, number>;
  delivered: Set<string>;
  deliveries: number;
}

/**
 * Sends `total` unique events at `ratePerS` (0 = as fast as `concurrency` allows), each
 * redelivered on non-2xx (store-like backoff, compressed: 200 ms..2 s), plus a duplicate
 * redelivery of `dupShare` of the acknowledged events.
 */
async function drive(port: () => number, total: number, opts: { ratePerS: number; concurrency: number; dupShare: number; prefix: string }, stats: RunStats) {
  const created = Math.floor(Date.now() / 1000);
  let next = 0;
  const one = async (i: number) => {
    const id = `${opts.prefix}_${i}`;
    const payload = stripeEvent(id, created);
    for (let attempt = 0; ; attempt++) {
      const r = await post(port(), payload);
      stats.deliveries++;
      stats.latencies.push(r.ms);
      if (process.env.DEBUG_SLOW && r.ms > 1000) console.error(`slow: sent at +${(performance.now() - start - r.ms).toFixed(0)} ms took ${r.ms.toFixed(0)} ms status ${r.status} attempt ${attempt}`);
      stats.statuses.set(r.status, (stats.statuses.get(r.status) ?? 0) + 1);
      if (r.status >= 200 && r.status < 300) {
        stats.delivered.add(id);
        break;
      }
      await sleep(Math.min(2_000, 200 * 2 ** attempt) * Math.random() + 50);
    }
    if (Math.random() < opts.dupShare) {
      const r = await post(port(), payload);
      stats.deliveries++;
      stats.statuses.set(r.status, (stats.statuses.get(r.status) ?? 0) + 1);
    }
  };
  if (process.env.WARMUP) for (let i = 0; i < Number(process.env.WARMUP); i++) await post(port(), stripeEvent(`warm_${opts.prefix}_${i}`, created));
  const start = performance.now();
  const workers = Array.from({ length: opts.concurrency }, async () => {
    while (next < total) {
      const i = next++;
      if (opts.ratePerS > 0) {
        const due = start + (i * 1000) / opts.ratePerS;
        const wait = due - performance.now();
        if (wait > 0) await sleep(wait);
      }
      await one(i);
    }
  });
  await Promise.all(workers);
  return (performance.now() - start) / 1000;
}

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]! : NaN;
};

async function scenario(name: string, fn: (ctx: {
  api: Awaited<ReturnType<typeof startApi>>; port: number; svc: Awaited<ReturnType<typeof startService>>;
  stats: RunStats; mem: number[];
}) => Promise<{ seconds: number; total: number; prefix: string } | void>, env: Record<string, string> = {}) {
  const api = await startApi();
  const port = 18_100 + Math.floor(Math.random() * 800);
  const svc = await startService(api.url, port, env);
  const stats: RunStats = { latencies: [], statuses: new Map(), delivered: new Set(), deliveries: 0 };
  const mem: number[] = [];
  let cpu = 0;
  const memTimer = setInterval(() => {
    mem.push(rssMb(svc.child));
    const c = cpuSeconds(svc.child);
    if (Number.isFinite(c)) cpu = c;
  }, 250);
  const genCpu0 = process.cpuUsage();
  const r = await fn({ api, port, svc, stats, mem });
  clearInterval(memTimer);
  if (process.env.DEBUG_METRICS) console.error(await fetch(`http://127.0.0.1:${port}/metrics`).then((x) => x.text(), () => ''));
  if (svc.child.exitCode === null) svc.child.kill('SIGTERM');
  await new Promise((res) => (svc.child.exitCode !== null ? res(null) : svc.child.once('exit', res)));
  api.close();
  if (!r) return;
  const lost = [...Array(r.total).keys()].map((i) => `${r.prefix}_${i}`).filter((id) => !api.st.applied.has(id));
  const dupApiCalls = [...api.st.applied.values()].reduce((a, n) => a + n - 1, 0);
  const ackedNotApplied = [...stats.delivered].filter((id) => !api.st.applied.has(id));
  const out = {
    scenario: name,
    events: r.total,
    deliveries: stats.deliveries,
    seconds: Number(r.seconds.toFixed(1)),
    rps: Math.round(stats.deliveries / r.seconds),
    p50_ms: Number(pct(stats.latencies, 50).toFixed(1)),
    p99_ms: Number(pct(stats.latencies, 99).toFixed(1)),
    max_ms: Number(Math.max(...stats.latencies).toFixed(1)),
    statuses: Object.fromEntries(stats.statuses),
    lost: lost.length,
    acked_but_not_applied: ackedNotApplied.length,
    duplicate_api_calls: dupApiCalls,
    api_requests: api.st.requests,
    api_peak_concurrency: api.st.peakInFlight,
    bad_signatures: api.st.badSig,
    service_cpu_s: cpu,
    loadgen_cpu_s: Number(((process.cpuUsage(genCpu0).user + process.cpuUsage(genCpu0).system) / 1e6).toFixed(1)),
    rss_mb_max: Number(Math.max(...mem.filter(Number.isFinite)).toFixed(0)),
    rss_mb_end: Number((mem.filter(Number.isFinite).at(-1) ?? NaN).toFixed(0)),
  };
  console.log(JSON.stringify(out));
  if (lost.length || ackedNotApplied.length || api.st.badSig) {
    console.error(svc.stderr().slice(-4000));
    process.exitCode = 1;
  }
}

const scenarios: Record<string, () => Promise<void>> = {
  // A renewal storm: 5,000 webhooks/min sustained for 30 s, 10% redelivered duplicates.
  steady: () => scenario('steady-5k-per-min', async ({ port, stats }) => {
    const total = 2_500;
    const seconds = await drive(() => port, total, { ratePerS: 5_000 / 60, concurrency: 64, dupShare: 0.1, prefix: 'steady' }, stats);
    return { seconds, total, prefix: 'steady' };
  }),
  // Max throughput: 20,000 events, 256 concurrent senders, api latency 15 ms.
  burst: () => scenario('burst-max', async ({ port, stats }) => {
    const total = 20_000;
    const seconds = await drive(() => port, total, { ratePerS: 0, concurrency: 256, dupShare: 0.1, prefix: 'burst' }, stats);
    return { seconds, total, prefix: 'burst' };
  }),
  // The api is down for 4 s in the middle of a 2,000/s burst, then recovers.
  'api-outage': () => scenario('api-outage', async ({ api, port, stats }) => {
    const total = 6_000;
    setTimeout(() => (api.st.down = true), 1_000);
    setTimeout(() => (api.st.down = false), 5_000);
    const seconds = await drive(() => port, total, { ratePerS: 2_000, concurrency: 256, dupShare: 0.05, prefix: 'outage' }, stats);
    return { seconds, total, prefix: 'outage' };
  }),
  // Redis unreachable from the start (500/s): dedupe fails open, webhooks keep flowing.
  'redis-outage': () => scenario('redis-outage', async ({ port, stats }) => {
    const total = 3_000;
    const seconds = await drive(() => port, total, { ratePerS: 500, concurrency: 128, dupShare: 0.1, prefix: 'noredis' }, stats);
    return { seconds, total, prefix: 'noredis' };
  }, { REDIS_URL: 'redis://127.0.0.1:1/0' }),
  // SIGTERM mid-burst: in-flight webhooks drain; anything refused is redelivered to a new replica.
  shutdown: () => scenario('sigterm-drain', async ({ api, port, svc, stats }) => {
    const total = 4_000;
    let currentPort = port;
    api.st.latencyMs = 100; // keep many forwards in flight at SIGTERM time
    let sigtermAt = 0;
    const exited = new Promise<{ code: number | null; ms: number }>((res) =>
      svc.child.once('exit', (code) => res({ code, ms: Math.round(performance.now() - sigtermAt) })));
    setTimeout(async () => {
      sigtermAt = performance.now();
      svc.child.kill('SIGTERM');
      const p2 = port + 1;
      await startService(api.url, p2).then((s2) => {
        currentPort = p2;
        process.once('beforeExit', () => s2.child.kill('SIGTERM'));
        setTimeout(() => s2.child.kill('SIGTERM'), 60_000).unref();
        (globalThis as { s2?: ChildProcess }).s2 = s2.child;
      });
    }, 1_500);
    const seconds = await drive(() => currentPort, total, { ratePerS: 1_000, concurrency: 256, dupShare: 0, prefix: 'drain' }, stats);
    (globalThis as { s2?: ChildProcess }).s2?.kill('SIGTERM');
    const ex = await exited;
    console.log(JSON.stringify({ first_replica_exit_code: ex.code, drain_ms: ex.ms }));
    return { seconds, total, prefix: 'drain' };
  }),
};

const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(scenarios);
for (const w of wanted) {
  const s = scenarios[w];
  if (!s) throw new Error(`unknown scenario ${w}`);
  await s();
}
agent.destroy();
{
  // Clean up the idempotency keys this run wrote (DB from REDIS_URL, default 7).
  const { Redis } = await import('ioredis');
  const r = new Redis(REDIS_URL, { maxRetriesPerRequest: 1 });
  let cursor = '0';
  do {
    const [c, keys] = await r.scan(cursor, 'MATCH', 'loadtest:*', 'COUNT', 1000);
    cursor = c;
    if (keys.length) await r.del(...keys);
  } while (cursor !== '0');
  await r.quit();
}
