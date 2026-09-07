/**
 * E2E: does the engine fail CLOSED when a REAL Postgres dies underneath it?
 *
 * Not "an adapter mock that throws on cue" - an actual container that is
 * `docker pause`d (TCP stays open, nothing ever answers) or `docker stop`ped
 * (sockets reset, then connection refused) while a check is in flight.
 *
 * This suite owns its own container, on an ephemeral port, with no
 * `duck-iam-e2e` label, so it can be frozen and killed without touching the
 * shared e2e Postgres other suites/agents depend on.
 *
 * The single invariant under test: an authorization system that cannot answer
 * must DENY. Every recorded verdict below is the value the CALLER received.
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect, createServer } from 'node:net'
import { promisify } from 'node:util'
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema } from '../../../test/e2e-env'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

const exec = promisify(execFile)

const PG_IMAGE = 'postgres:16-alpine'
const PG_USER = 'duckiam'
const PG_PASSWORD = 'duckiam'
const PG_DB = 'duckiam_resilience'
const READY_TIMEOUT_MS = 90_000

async function docker(args: string[], timeout = 90_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

/**
 * Pick a free host port up front and publish the container on it explicitly.
 *
 * `-p 0:5432` cannot be used here: docker re-picks the ephemeral host port on
 * every `docker start`, so a container this suite stops and restarts would come
 * back on a different port and every later engine would see a dead URL - a
 * harness artefact that reads exactly like a fail-closed deny.
 */
async function freePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const srv = createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      if (addr === null || typeof addr === 'string') {
        srv.close()
        reject(new Error('could not allocate a port'))
        return
      }
      const { port } = addr
      srv.close(() => resolve(port))
    })
  })
}

async function waitUntilReady(name: string, probe: string[]): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let last = ''
  while (Date.now() < deadline) {
    try {
      await docker(['exec', name, ...probe], 15_000)
      return
    } catch (err) {
      last = err instanceof Error ? err.message : String(err)
      await new Promise((r) => setTimeout(r, 250))
    }
  }
  throw new Error(`${name} never became ready: ${last}`)
}

async function waitUntilReachable(port: number): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const socket = connect({ host: '127.0.0.1', port })
      const done = (r: boolean) => {
        socket.destroy()
        resolve(r)
      }
      socket.once('connect', () => done(true))
      socket.once('error', () => done(false))
      socket.setTimeout(1000, () => done(false))
    })
    if (ok) return
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error(`127.0.0.1:${port} never accepted a connection`)
}

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }
type Role = 'admin'

let containerName = ''
let url = ''
/** Pool used only by the suite itself for fixtures; never the engine's. */
let fixturePool: Pool
/** Every pool an engine was built on, so afterAll can drain them. */
const pools: Pool[] = []

interface IEngineOpts {
  adapterTimeoutMs?: number
  cacheTTL?: number
  onError?: (err: Error) => void
  poolMax?: number
}

/**
 * Fresh pool + adapter per engine, so one test's dead sockets cannot be
 * mistaken for the next test's verdict.
 */
function adapterFor(opts: IEngineOpts): IamDrizzleAdapter<string, string, Role, string> {
  const pool = new Pool({ connectionString: url, max: opts.poolMax ?? 10 })
  // pg emits `error` on the Pool for a socket that dies while idle. With no
  // listener Node turns that into an unhandled 'error' event and kills the
  // worker - which is a property of pg, not of duck-iam, so the suite absorbs
  // it rather than letting it mask the verdict under test.
  pool.on('error', () => {})
  pools.push(pool)
  return new IamDrizzleAdapter<string, string, Role, string>({ db: drizzle(pool), ops: OPS, tables: TABLES })
}

function makeEngine(opts: IEngineOpts): IamEngine<string, string, Role, string, 'development'> {
  return new IamEngine<string, string, Role, string, 'development'>({
    adapter: adapterFor(opts),
    adapterTimeoutMs: opts.adapterTimeoutMs ?? 1500,
    cacheTTL: opts.cacheTTL ?? 0,
    mode: 'development',
    ...(opts.onError ? { hooks: { onError: (e: Error) => opts.onError?.(e) } } : {}),
  })
}

function makeProdEngine(opts: IEngineOpts): IamEngine<string, string, Role, string, 'production'> {
  return new IamEngine<string, string, Role, string, 'production'>({
    adapter: adapterFor(opts),
    adapterTimeoutMs: opts.adapterTimeoutMs ?? 1500,
    cacheTTL: opts.cacheTTL ?? 0,
    mode: 'production',
    ...(opts.onError ? { hooks: { onError: (e: Error) => opts.onError?.(e) } } : {}),
  })
}

/** Truth table for the whole suite: `u1` holds `admin`, `admin` may `read doc`. */
async function seed(): Promise<void> {
  const boot = makeEngine({ adapterTimeoutMs: 10_000 })
  await boot.admin.saveRole({ id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
  await boot.admin.assignRole('u1', 'admin')
}

beforeAll(async () => {
  // Fail loudly, never skip: a green run with no docker certifies nothing.
  await docker(['info', '--format', '{{.ServerVersion}}'], 10_000)
  containerName = `duck-iam-resilience-kill-${randomBytes(4).toString('hex')}`
  const port = await freePort()
  await docker([
    'run',
    '-d',
    '--name',
    containerName,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    `127.0.0.1:${port}:5432`,
    '-e',
    `POSTGRES_USER=${PG_USER}`,
    '-e',
    `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e',
    `POSTGRES_DB=${PG_DB}`,
    PG_IMAGE,
  ])
  await waitUntilReady(containerName, ['pg_isready', '-U', PG_USER, '-d', PG_DB])
  await waitUntilReady(containerName, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  await waitUntilReachable(port)
  url = `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
  fixturePool = new Pool({ connectionString: url })
  fixturePool.on('error', () => {})
  await applyPgSchema(fixturePool)
  await seed()
}, 180_000)

afterAll(async () => {
  if (containerName) {
    // Unfreeze before draining: `pool.end()` waits on queries that a paused
    // container will never answer.
    await docker(['unpause', containerName]).catch(() => {})
    await docker(['start', containerName]).catch(() => {})
  }
  await Promise.all(pools.map((p) => p.end().catch(() => {})))
  await fixturePool?.end().catch(() => {})
  if (containerName) await docker(['rm', '-f', '-v', containerName]).catch(() => {})
}, 120_000)

/** Freeze the database for the duration of `body`, then thaw it. */
async function whilePaused<T>(body: () => Promise<T>): Promise<T> {
  await docker(['pause', containerName])
  try {
    return await body()
  } finally {
    await docker(['unpause', containerName])
  }
}

/** Kill the database for the duration of `body`, then bring it back. */
async function whileStopped<T>(body: () => Promise<T>): Promise<T> {
  await docker(['stop', '-t', '0', containerName])
  try {
    return await body()
  } finally {
    await docker(['start', containerName])
    await waitUntilReady(containerName, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  }
}

describe('E2E fail-closed: Postgres frozen (docker pause) mid-flight', () => {
  it('a cold check against a frozen database denies, and reports the failure', async () => {
    const errors: Error[] = []
    const engine = makeEngine({ onError: (e) => errors.push(e) })

    const decision = await whilePaused(() => engine.check('u1', 'read', { attributes: {}, type: 'doc' }))

    expect(typeof decision).toBe('object')
    const d = decision
    expect(d.allowed).toBe(false)
    expect(d.effect).toBe('deny')
    // The verdict is what matters; the discriminant is what an operator sees.
    expect(d.failure).toBeDefined()
    expect(errors.length).toBeGreaterThan(0)
  }, 60_000)

  it('can() denies against a frozen database', async () => {
    const engine = makeEngine({})
    const allowed = await whilePaused(() => engine.can('u1', 'read', { attributes: {}, type: 'doc' }))
    expect(allowed).toBe(false)
  }, 60_000)

  it('production mode denies against a frozen database', async () => {
    const engine = makeProdEngine({})
    const result = await whilePaused(() => engine.check('u1', 'read', { attributes: {}, type: 'doc' }))
    expect(result).toBe(false)
  }, 60_000)

  it('the database freezing DURING an in-flight check still denies', async () => {
    const errors: Error[] = []
    // Warm nothing: cacheTTL 0. The check starts, then the floor disappears.
    const engine = makeEngine({ onError: (e) => errors.push(e) })
    const inFlight = engine.check('u1', 'read', { attributes: {}, type: 'doc' })
    await docker(['pause', containerName])
    let d: AccessControl.IDecision
    try {
      d = await inFlight
    } finally {
      await docker(['unpause', containerName])
    }
    // Either the query completed in the race window (allow, legitimately) or it
    // did not (must be deny). What must never happen is an allow produced by
    // the failure.
    if (d.allowed) {
      expect(errors).toEqual([])
    } else {
      expect(d.effect).toBe('deny')
    }
  }, 60_000)

  it('a batch permissions() call against a frozen database denies every entry', async () => {
    const errors: Error[] = []
    const engine = makeEngine({ onError: (e) => errors.push(e) })

    const map = await whilePaused(() =>
      engine.permissions('u1', [
        { action: 'read', resource: 'doc' },
        { action: 'write', resource: 'doc' },
        { action: 'read', resource: 'doc', resourceId: 'd1' },
      ]),
    )

    expect(Object.keys(map)).toHaveLength(3)
    for (const [key, value] of Object.entries(map)) {
      expect(value, `permissions()[${key}] must fail closed`).toBe(false)
    }
    expect(errors.length).toBeGreaterThan(0)
  }, 60_000)

  it('40 concurrent checks against a frozen database all deny', async () => {
    const engine = makeEngine({ poolMax: 5 })
    const subjects = Array.from({ length: 40 }, (_, i) => `conc-${i}`)

    const results = await whilePaused(async () =>
      Promise.all(subjects.map((s) => engine.can(s, 'read', { attributes: {}, type: 'doc' }))),
    )

    expect(results.every((r) => r === false)).toBe(true)
  }, 90_000)

  it('the engine recovers once the database comes back', async () => {
    const engine = makeEngine({})
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)

    expect(await whilePaused(() => engine.can('u1', 'read', { attributes: {}, type: 'doc' }))).toBe(false)

    // Same engine instance, no invalidation, no restart.
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)
  }, 90_000)

  it('a failed shared load does not poison later callers, and a later success repopulates', async () => {
    const engine = makeEngine({})

    // Two callers joining the SAME in-flight load both see the failure.
    const both = await whilePaused(async () => {
      const a = engine.can('u1', 'read', { attributes: {}, type: 'doc' })
      const b = engine.can('u1', 'read', { attributes: {}, type: 'doc' })
      return Promise.all([a, b])
    })
    expect(both).toEqual([false, false])

    // A caller arriving after the rejection must get a fresh load, not the
    // rejected promise held in the single-flight slot.
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)
  }, 90_000)
})

describe('E2E fail-closed: Postgres killed (docker stop) mid-flight', () => {
  it('a check against a stopped database denies', async () => {
    const errors: Error[] = []
    const engine = makeEngine({ onError: (e) => errors.push(e) })

    const d = await whileStopped(() => engine.check('u1', 'read', { attributes: {}, type: 'doc' }))

    expect(d.allowed).toBe(false)
    expect(errors.length).toBeGreaterThan(0)
  }, 120_000)

  it('the engine recovers after the database is restarted', async () => {
    const engine = makeEngine({})
    expect(await whileStopped(() => engine.can('u1', 'read', { attributes: {}, type: 'doc' }))).toBe(false)
    // The pool is holding dead sockets; recovery means it discards them.
    let recovered = false
    const deadline = Date.now() + 30_000
    while (Date.now() < deadline && !recovered) {
      recovered = await engine.can('u1', 'read', { attributes: {}, type: 'doc' })
      if (!recovered) await new Promise((r) => setTimeout(r, 500))
    }
    expect(recovered).toBe(true)
  }, 150_000)
})

describe('E2E fail-closed: a cached ALLOW plus an unreachable backend', () => {
  it('stops serving the cached allow within cacheTTL, and does not extend it', async () => {
    const ttlSeconds = 2
    const engine = makeEngine({ adapterTimeoutMs: 800, cacheTTL: ttlSeconds })

    // Warm every cache with a genuine allow.
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)

    const observed: { allowed: boolean; at: number }[] = []
    const t0 = Date.now()
    await docker(['pause', containerName])
    try {
      // Poll well past the TTL. If the answer is still `true` at the end, a
      // dead backend is extending a stale grant - the dangerous case.
      const deadline = t0 + ttlSeconds * 1000 + 8_000
      while (Date.now() < deadline) {
        const allowed = await engine.can('u1', 'read', { attributes: {}, type: 'doc' })
        observed.push({ allowed, at: Date.now() - t0 })
        if (!allowed) break
        await new Promise((r) => setTimeout(r, 100))
      }
    } finally {
      await docker(['unpause', containerName])
    }

    const firstDeny = observed.find((o) => !o.allowed)
    // Reported so the number is in the record, not just the pass/fail.
    console.info(
      `[resilience] cached allow survived a frozen backend for ${firstDeny ? `${firstDeny.at}ms` : '>TTL+8000ms (NEVER DENIED)'} (cacheTTL=${ttlSeconds * 1000}ms, adapterTimeout=800ms)`,
    )
    expect(firstDeny, 'a cached allow outlived its TTL against a dead backend').toBeDefined()
    // TTL + one adapter timeout + poll slack. Anything beyond that is a stale
    // grant extended by the failure itself.
    expect(firstDeny?.at).toBeLessThan(ttlSeconds * 1000 + 800 + 2_000)
  }, 120_000)
})
