// E2E: resets, hangs, late responses, partial outages and exhaustion through a TCP proxy must all DENY.
// Owns its own Postgres container on a free port, so the shared e2e Postgres is never touched.
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect, createServer, type Server, type Socket } from 'node:net'
import { promisify } from 'node:util'
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema } from '../../../test/e2e-env'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

const exec = promisify(execFile)

const PG_IMAGE = 'postgres:18.4-alpine3.24'
const PG_USER = 'duckiam'
const PG_PASSWORD = 'duckiam'
const PG_DB = 'duckiam_net'
const READY_TIMEOUT_MS = 90_000

async function docker(args: string[], timeout = 90_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

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

/**
 * A TCP proxy whose failure mode is switchable at runtime.
 * `blackhole` accepts and never answers, so only the engine's own timeout can end the wait.
 */
class FaultProxy {
  mode: 'pass' | 'blackhole' = 'pass'
  /** Milliseconds to hold each server->client chunk, so a response can land after the engine gave up. */
  delayMs = 0
  /** When set, the next client->server chunk RSTs the pair instead of being forwarded. */
  resetOnNextQuery = false
  private _pairs = new Set<{ client: Socket; upstream: Socket }>()
  private _server: Server | null = null
  port = 0

  constructor(private readonly upstreamPort: number) {}

  async listen(): Promise<void> {
    this.port = await freePort()
    const server = createServer((client) => {
      const upstream = connect({ host: '127.0.0.1', port: this.upstreamPort })
      const pair = { client, upstream }
      this._pairs.add(pair)
      const teardown = () => {
        this._pairs.delete(pair)
        client.destroy()
        upstream.destroy()
      }
      client.on('error', teardown)
      upstream.on('error', teardown)
      client.on('close', teardown)
      upstream.on('close', teardown)
      client.on('data', (chunk) => {
        if (this.resetOnNextQuery) {
          this.resetOnNextQuery = false
          this.killNow()
          return
        }
        if (this.mode === 'blackhole') return
        upstream.write(chunk)
      })
      upstream.on('data', (chunk) => {
        if (this.mode === 'blackhole') return
        if (this.delayMs > 0) {
          const held = this.delayMs
          setTimeout(() => {
            if (!client.destroyed) client.write(chunk)
          }, held)
          return
        }
        client.write(chunk)
      })
    })
    this._server = server
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(this.port, '127.0.0.1', () => resolve())
    })
  }

  /** RST every live connection - what a mid-flight reset actually looks like. */
  killNow(): void {
    for (const pair of this._pairs) {
      // `resetAndDestroy` sends RST, not FIN: the network ate it, not a polite close.
      pair.client.resetAndDestroy()
      pair.upstream.destroy()
    }
    this._pairs.clear()
  }

  healthy(): void {
    this.mode = 'pass'
    this.delayMs = 0
    this.resetOnNextQuery = false
  }

  async close(): Promise<void> {
    this.killNow()
    const server = this._server
    if (!server) return
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
}

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }
type Role = string

let containerName = ''
let pgPort = 0
/** Direct (unproxied) URL, for fixtures. */
let directUrl = ''
let fixturePool: Pool
const pools: Pool[] = []
const proxies: FaultProxy[] = []

function urlFor(port: number, db = PG_DB): string {
  return `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${db}`
}

function poolFor(port: number, db = PG_DB, max = 10): Pool {
  const pool = new Pool({ connectionString: urlFor(port, db), max })
  // INFO: pg emits `error` on the Pool when an idle socket dies; unhandled, it kills the worker.
  pool.on('error', () => {})
  pools.push(pool)
  return pool
}

function adapterOn(pool: Pool): IamDrizzleAdapter<string, string, Role, string> {
  return new IamDrizzleAdapter<string, string, Role, string>({ db: drizzle(pool), ops: OPS, tables: TABLES })
}

function engineOn(
  adapter: IamAdapter.IAdapter<string, string, Role, string>,
  opts: { adapterTimeoutMs?: number; cacheTTL?: number; maxPolicies?: number; onError?: (e: Error) => void } = {},
): IamEngine<string, string, Role, string, 'development'> {
  return new IamEngine<string, string, Role, string, 'development'>({
    adapter,
    adapterTimeoutMs: opts.adapterTimeoutMs ?? 1000,
    cacheTTL: opts.cacheTTL ?? 0,
    mode: 'development',
    ...(opts.maxPolicies ? { maxPolicies: opts.maxPolicies } : {}),
    ...(opts.onError ? { hooks: { onError: (e: Error) => opts.onError?.(e) } } : {}),
  })
}

/**
 * Asserts the healthy path allows before a fault is armed. Retries because the shared pool can still hold
 * the previous test's RST'd sockets; still fails if the pool never recovers.
 */
async function baselineAllows(engine: IamEngine<string, string, Role, string, 'development'>): Promise<void> {
  const deadline = Date.now() + 5_000
  let allowed = false
  while (Date.now() < deadline) {
    allowed = await engine.can('u1', 'read', DOC)
    if (allowed) return
    await new Promise((r) => setTimeout(r, 100))
  }
  expect(allowed, 'the healthy path never recovered, so no fault below is being measured').toBe(true)
}

type ReadMethod = 'listPolicies' | 'listRoles' | 'getSubjectRoles' | 'getSubjectAttributes'

/** A real drizzle adapter whose read methods can each be routed to a second real adapter behind a breakable proxy. */
class SplitAdapter extends IamDrizzleAdapter<string, string, Role, string> {
  /** Methods routed to the breakable half. */
  broken = new Set<ReadMethod>()

  constructor(
    healthy: Pool,
    private readonly other: IamDrizzleAdapter<string, string, Role, string>,
  ) {
    super({ db: drizzle(healthy), ops: OPS, tables: TABLES })
  }

  override listPolicies(opts?: IamAdapter.IReadOptions) {
    return this.broken.has('listPolicies') ? this.other.listPolicies(opts) : super.listPolicies(opts)
  }
  override listRoles(opts?: IamAdapter.IReadOptions) {
    return this.broken.has('listRoles') ? this.other.listRoles(opts) : super.listRoles(opts)
  }
  override getSubjectRoles(subjectId: string, opts?: IamAdapter.IReadOptions) {
    return this.broken.has('getSubjectRoles')
      ? this.other.getSubjectRoles(subjectId, opts)
      : super.getSubjectRoles(subjectId, opts)
  }
  override getSubjectAttributes(subjectId: string, opts?: IamAdapter.IReadOptions) {
    return this.broken.has('getSubjectAttributes')
      ? this.other.getSubjectAttributes(subjectId, opts)
      : super.getSubjectAttributes(subjectId, opts)
  }
}

let proxy: FaultProxy
let proxyPool: Pool

beforeAll(async () => {
  // Loud, never skipped.
  await docker(['info', '--format', '{{.ServerVersion}}'], 10_000)
  containerName = `duck-iam-resilience-net-${randomBytes(4).toString('hex')}`
  pgPort = await freePort()
  await docker([
    'run',
    '-d',
    '--name',
    containerName,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    `127.0.0.1:${pgPort}:5432`,
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
  directUrl = urlFor(pgPort)
  fixturePool = new Pool({ connectionString: directUrl })
  fixturePool.on('error', () => {})
  await applyPgSchema(fixturePool)

  // Fixture: `u1` holds `admin`, `admin` may `read doc` and nothing else.
  const boot = engineOn(adapterOn(poolFor(pgPort)), { adapterTimeoutMs: 15_000 })
  await boot.admin.saveRole({ id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
  await boot.admin.assignRole('u1', 'admin')

  proxy = new FaultProxy(pgPort)
  await proxy.listen()
  proxies.push(proxy)
  proxyPool = poolFor(proxy.port)
}, 180_000)

afterAll(async () => {
  for (const p of proxies) await p.close().catch(() => {})
  await Promise.all(pools.map((p) => p.end().catch(() => {})))
  await fixturePool?.end().catch(() => {})
  if (containerName) await docker(['rm', '-f', '-v', containerName]).catch(() => {})
}, 120_000)

const DOC = { attributes: {}, type: 'doc' } as const

describe('E2E fail-closed: connection reset mid-flight', () => {
  it('an RST on the socket carrying the query denies', async () => {
    proxy.healthy()
    const errors: Error[] = []
    const engine = engineOn(adapterOn(proxyPool), { adapterTimeoutMs: 4000, onError: (e) => errors.push(e) })

    // Establish the connection and prove the fixture allows before breaking it.
    await baselineAllows(engine)

    // Arm: the next byte the driver writes (the query) RSTs the pair instead.
    proxy.resetOnNextQuery = true
    const t0 = Date.now()
    const allowed = await engine.can('u1', 'read', DOC)
    const elapsed = Date.now() - t0

    expect(allowed).toBe(false)
    expect(errors.length).toBeGreaterThan(0)
    // A reset is an immediate error, so it must not cost the full adapter timeout.
    expect(elapsed).toBeLessThan(4000)
  }, 60_000)

  it('an RST during a batch permissions() denies every entry', async () => {
    proxy.healthy()
    const engine = engineOn(adapterOn(proxyPool), { adapterTimeoutMs: 4000 })
    await baselineAllows(engine)

    proxy.resetOnNextQuery = true
    const map = await engine.permissions('u1', [
      { action: 'read', resource: 'doc' },
      { action: 'write', resource: 'doc' },
    ])

    for (const [key, value] of Object.entries(map)) {
      expect(value, `permissions()[${key}] must fail closed on a reset`).toBe(false)
    }
  }, 60_000)
})

describe('E2E fail-closed: a hung connection that never answers', () => {
  it('_withTimeout fires and the caller gets a deny, bounded by adapterTimeoutMs', async () => {
    proxy.healthy()
    const errors: Error[] = []
    const engine = engineOn(adapterOn(proxyPool), { adapterTimeoutMs: 900, onError: (e) => errors.push(e) })
    await baselineAllows(engine)

    proxy.mode = 'blackhole'
    const t0 = Date.now()
    const d = await engine.check('u1', 'read', DOC)
    const elapsed = Date.now() - t0
    proxy.healthy()

    console.info(`[resilience] hung connection: verdict=${d.allowed ? 'ALLOW' : 'deny'} after ${elapsed}ms`)
    expect(d.allowed).toBe(false)
    expect(errors.length).toBeGreaterThan(0)
    // A generous bound: this asserts the timeout fires, not how fast.
    expect(elapsed).toBeLessThan(6000)
  }, 60_000)

  it('a hung backend denies every entry of a batch, and returns', async () => {
    proxy.healthy()
    const engine = engineOn(adapterOn(proxyPool), { adapterTimeoutMs: 900 })
    await baselineAllows(engine)

    proxy.mode = 'blackhole'
    const t0 = Date.now()
    const map = await engine.permissions('u1', [
      { action: 'read', resource: 'doc' },
      { action: 'read', resource: 'doc', resourceId: 'x' },
      { action: 'write', resource: 'doc' },
    ])
    const elapsed = Date.now() - t0
    proxy.healthy()

    expect(Object.values(map)).toEqual([false, false, false])
    expect(elapsed).toBeLessThan(15_000)
  }, 60_000)
})

describe('E2E fail-closed: a correct response that arrives after the timeout', () => {
  it('the late response is not used to answer, and is not cached as an allow', async () => {
    proxy.healthy()
    // Long TTL on purpose: a late load that lands in the cache could answer the next check.
    const engine = engineOn(adapterOn(proxyPool), { adapterTimeoutMs: 700, cacheTTL: 60 })

    // Hold every response for well past the timeout. Nothing is cached yet.
    proxy.delayMs = 2000
    const t0 = Date.now()
    const first = await engine.can('u1', 'read', DOC)
    const elapsed = Date.now() - t0
    expect(first, 'a response that arrived after the timeout must not answer').toBe(false)
    expect(elapsed).toBeLessThan(2000)

    // Let the late response land, then hang the backend: an allow now can only come from the cache.
    await new Promise((r) => setTimeout(r, 3000))
    proxy.delayMs = 0
    proxy.mode = 'blackhole'
    const second = await engine.can('u1', 'read', DOC)
    proxy.healthy()

    console.info(`[resilience] late-response reuse: second check (backend hung) = ${second ? 'ALLOW' : 'deny'}`)
    expect(second, 'a response the engine had already timed out on was cached and served as an allow').toBe(false)
  }, 90_000)
})

describe('E2E fail-closed: partial backend failure', () => {
  /** A split adapter: healthy half direct, breakable half through its own proxy. */
  async function splitRig(): Promise<{ adapter: SplitAdapter; broken: FaultProxy }> {
    const broken = new FaultProxy(pgPort)
    await broken.listen()
    proxies.push(broken)
    const adapter = new SplitAdapter(poolFor(pgPort), adapterOn(poolFor(broken.port)))
    return { adapter, broken }
  }

  for (const method of ['listRoles', 'listPolicies', 'getSubjectRoles', 'getSubjectAttributes'] as ReadMethod[]) {
    it(`denies when only ${method} is unreachable`, async () => {
      const { adapter, broken } = await splitRig()
      const errors: Error[] = []
      const engine = engineOn(adapter, { adapterTimeoutMs: 900, onError: (e) => errors.push(e) })

      // A healthy allow first, so the deny below is down to the partial failure alone.
      await baselineAllows(engine)

      adapter.broken.add(method)
      broken.mode = 'blackhole'
      const d = await engine.check('u1', 'read', DOC)
      console.info(`[resilience] only ${method} down: verdict=${d.allowed ? 'ALLOW' : 'deny'} (${d.reason})`)

      expect(d.allowed, `a check with only ${method} unreachable must deny`).toBe(false)
      expect(errors.length).toBeGreaterThan(0)

      await broken.close()
    }, 60_000)
  }

  it('denies a batch when only the merged policy load is unreachable', async () => {
    const { adapter, broken } = await splitRig()
    const engine = engineOn(adapter, { adapterTimeoutMs: 900 })
    await baselineAllows(engine)

    // The subject still resolves on the healthy half; only the policy load is gone.
    adapter.broken.add('listPolicies')
    broken.mode = 'blackhole'
    const map = await engine.permissions('u1', [
      { action: 'read', resource: 'doc' },
      { action: 'write', resource: 'doc' },
    ])
    expect(Object.values(map)).toEqual([false, false])
    await broken.close()
  }, 60_000)
})

describe('E2E fail-closed: resource exhaustion', () => {
  it('an exhausted connection pool denies rather than hanging', async () => {
    const pool = poolFor(pgPort, PG_DB, 1)
    const engine = engineOn(adapterOn(pool), { adapterTimeoutMs: 900 })
    await baselineAllows(engine)

    // Take the pool's only connection and keep it busy.
    const held = await pool.connect()
    const busy = held.query('SELECT pg_sleep(20)').catch(() => {})

    const t0 = Date.now()
    const d = await engine.check('u1', 'read', DOC)
    const elapsed = Date.now() - t0

    console.info(`[resilience] pool exhausted: verdict=${d.allowed ? 'ALLOW' : 'deny'} after ${elapsed}ms`)
    expect(d.allowed).toBe(false)
    expect(elapsed).toBeLessThan(6000)

    held.release(true)
    await busy
  }, 60_000)

  it('more policies than maxPolicies denies instead of evaluating a truncated set', async () => {
    const engine = engineOn(adapterOn(poolFor(pgPort)), { adapterTimeoutMs: 5000, maxPolicies: 1 })
    // Two policies exist once these are saved; the cap is 1.
    const boot = engineOn(adapterOn(poolFor(pgPort)), { adapterTimeoutMs: 5000 })
    await boot.admin.savePolicy({
      algorithm: 'deny-overrides',
      id: 'cap-a',
      name: 'cap-a',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources: ['doc'] },
      ],
      version: 1,
    })
    await boot.admin.savePolicy({
      algorithm: 'deny-overrides',
      id: 'cap-b',
      name: 'cap-b',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources: ['doc'] },
      ],
      version: 1,
    })

    const d = await engine.check('u1', 'read', DOC)
    console.info(`[resilience] maxPolicies exceeded: verdict=${d.allowed ? 'ALLOW' : 'deny'}`)
    expect(d.allowed).toBe(false)

    await boot.admin.deletePolicy('cap-a')
    await boot.admin.deletePolicy('cap-b')
  }, 60_000)
})

describe('E2E fail-closed: oversized catalogs on the interpreter fallback', () => {
  // More than 32 roles forces the interpreter. Its own database keeps the extra roles out of the suites above.
  let bigPool: Pool
  let bigProxy: FaultProxy
  const BIG_DB = 'duckiam_net_big'

  beforeAll(async () => {
    await fixturePool.query(`CREATE DATABASE ${BIG_DB}`)
    const admin = new Pool({ connectionString: urlFor(pgPort, BIG_DB) })
    admin.on('error', () => {})
    await applyPgSchema(admin)
    await admin.end()

    bigProxy = new FaultProxy(pgPort)
    await bigProxy.listen()
    proxies.push(bigProxy)
    bigPool = poolFor(bigProxy.port, BIG_DB)

    const boot = engineOn(adapterOn(poolFor(pgPort, BIG_DB)), { adapterTimeoutMs: 30_000 })
    for (let i = 0; i < 40; i++) {
      await boot.admin.saveRole({ id: `r${i}`, name: `r${i}`, permissions: [{ action: 'read', resource: `t${i}` }] })
    }
    for (let i = 0; i < 200; i++) {
      await boot.admin.savePolicy({
        algorithm: 'deny-overrides',
        id: `p${i}`,
        name: `p${i}`,
        rules: [
          {
            actions: ['noop'],
            conditions: { all: [] },
            effect: 'allow',
            id: 'r',
            priority: 0,
            resources: [`none${i}`],
          },
        ],
        version: 1,
      })
    }
    await boot.admin.assignRole('big-user', 'r0')
  }, 180_000)

  it('answers correctly with 40 roles and 200 policies (interpreter path)', async () => {
    bigProxy.healthy()
    const engine = engineOn(adapterOn(bigPool), { adapterTimeoutMs: 10_000 })
    expect(await engine.can('big-user', 'read', { attributes: {}, type: 't0' })).toBe(true)
    expect(await engine.can('big-user', 'read', { attributes: {}, type: 't1' })).toBe(false)
  }, 90_000)

  it('denies on the interpreter path when the backend hangs', async () => {
    bigProxy.healthy()
    const engine = engineOn(adapterOn(bigPool), { adapterTimeoutMs: 900 })
    expect(await engine.can('big-user', 'read', { attributes: {}, type: 't0' })).toBe(true)

    bigProxy.mode = 'blackhole'
    const d = await engine.check('big-user', 'read', { attributes: {}, type: 't0' })
    bigProxy.healthy()

    console.info(`[resilience] interpreter path, backend hung: ${d.allowed ? 'ALLOW' : 'deny'}`)
    expect(d.allowed).toBe(false)
  }, 90_000)

  it('denies on the interpreter path when the socket is reset mid-query', async () => {
    bigProxy.healthy()
    const engine = engineOn(adapterOn(bigPool), { adapterTimeoutMs: 4000 })
    expect(await engine.can('big-user', 'read', { attributes: {}, type: 't0' })).toBe(true)

    bigProxy.resetOnNextQuery = true
    const allowed = await engine.can('big-user', 'read', { attributes: {}, type: 't0' })
    expect(allowed).toBe(false)
  }, 90_000)
})
