/**
 * E2E: multi-instance revocation fan-out.
 *
 * Validates the load-bearing assumption behind
 * `plans/C3-engine/01-jwt-instant-revocation.md`: that a revocation published on
 * one instance reaches every other instance over pub/sub, fast enough that an
 * in-memory registry is a safe substitute for a per-request Redis read.
 *
 * **This cannot be tested in a single process.** One instance both publishes and
 * subscribes, and `RedisEvents` dedupes its own messages by instance id, so the
 * fan-out path never runs. Real child processes are the only way.
 *
 * The registry itself is not built yet — these tests validate the *design* so
 * the plan is de-risked before implementation.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset.
 */
import { type ChildProcess, spawn } from 'node:child_process'
import { join } from 'node:path'
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { e2ePrefix, instanceCount, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip
const WORKER = join(process.cwd(), 'src/test/e2e-revocation-worker.ts')

type Observation = {
  workerId: string
  identityId: string
  publishedAt: number
  receivedAt: number
  latencyMs: number
  registrySize: number
}

suite('E2E multi-instance revocation fan-out (real Redis, real processes)', () => {
  let redis: Redis
  let runId: string
  let workers: ChildProcess[] = []
  const N = Math.max(2, instanceCount())

  /** Publish in the exact envelope shape RedisEvents expects from a peer. */
  async function publishRevocation(identityId: string): Promise<number> {
    const at = Date.now()
    await redis.publish(
      'auth:events:authz.revoked',
      JSON.stringify({ from: 'test-publisher', payload: { identityId, at } }),
    )
    return at
  }

  async function results(): Promise<Observation[]> {
    const raw = await redis.lrange(`${runId}:results`, 0, -1)
    return raw.map((r) => JSON.parse(r) as Observation)
  }

  beforeAll(async () => {
    redis = new Redis(URL as string)
    runId = e2ePrefix()

    for (let i = 0; i < N; i++) {
      workers.push(
        spawn('bun', ['run', WORKER, URL as string, runId, `w${i}`], {
          cwd: process.cwd(),
          stdio: ['ignore', 'ignore', 'pipe'],
        }),
      )
    }

    // Wait for every worker to report its subscription is live.
    const deadline = Date.now() + 20_000
    for (;;) {
      const ready = await redis.llen(`${runId}:ready`)
      if (ready >= N) break
      if (Date.now() > deadline) throw new Error(`only ${ready}/${N} workers came up`)
      await new Promise((r) => setTimeout(r, 100))
    }
  }, 30_000)

  afterAll(async () => {
    for (const w of workers) w.kill('SIGKILL')
    workers = []
    if (redis) {
      for (const k of await redis.keys(`${runId}*`)) await redis.del(k)
      await redis.quit()
    }
  })

  it(`reaches all ${N} instances`, async () => {
    await publishRevocation('ident-fanout')
    await new Promise((r) => setTimeout(r, 1500))

    const got = (await results()).filter((o) => o.identityId === 'ident-fanout')
    const distinct = new Set(got.map((o) => o.workerId))

    expect(distinct.size).toBe(N)
  }, 20_000)

  it('propagates fast enough for an in-memory registry to be safe', async () => {
    const samples: number[] = []
    for (let i = 0; i < 5; i++) {
      await publishRevocation(`ident-latency-${i}`)
      await new Promise((r) => setTimeout(r, 400))
    }
    const got = await results()
    for (const o of got.filter((x) => x.identityId.startsWith('ident-latency-'))) {
      samples.push(o.latencyMs)
    }

    expect(samples.length).toBeGreaterThan(0)
    const max = Math.max(...samples)
    const avg = Math.round(samples.reduce((a, b) => a + b, 0) / samples.length)

    // Recorded for the plan: if this were seconds rather than milliseconds, the
    // push design would be unsafe and a per-request read would be required.
    await redis.set(`${runId}:latency`, JSON.stringify({ avg, max, n: samples.length }))

    expect(max).toBeLessThan(1000)
  }, 30_000)

  it('accumulates independently per instance', async () => {
    await publishRevocation('ident-a')
    await new Promise((r) => setTimeout(r, 300))
    await publishRevocation('ident-b')
    await new Promise((r) => setTimeout(r, 800))

    const got = await results()
    const perWorker = new Map<string, number>()
    for (const o of got) perWorker.set(o.workerId, Math.max(perWorker.get(o.workerId) ?? 0, o.registrySize))

    // Every instance holds the full set, not a shard of it.
    expect(perWorker.size).toBe(N)
    for (const size of perWorker.values()) expect(size).toBeGreaterThanOrEqual(2)
  }, 20_000)

  it('a late-joining instance misses everything published before it — proving warm() is required', async () => {
    await publishRevocation('ident-before-join')
    await new Promise((r) => setTimeout(r, 500))

    const lateId = 'late'
    const late = spawn('bun', ['run', WORKER, URL as string, runId, lateId], {
      cwd: process.cwd(),
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    workers.push(late)
    await new Promise((r) => setTimeout(r, 1500))

    const seenByLate = (await results()).filter((o) => o.workerId === lateId)

    // The late instance has NO record of the earlier revocation. This is the
    // cold-start hole plan C3-engine/01 closes with a boot-time warm() from
    // Redis — without it, a restarted or scaled-out instance honours tokens
    // that were revoked while it was down.
    expect(seenByLate.some((o) => o.identityId === 'ident-before-join')).toBe(false)
  }, 30_000)
})
