/**
 * E2E: network-level nastiness between the engine and a REAL Postgres.
 *
 * `docker pause` proves the coarse case. This suite proves the precise ones,
 * by putting a TCP proxy this file controls between the pg driver and the
 * database and then doing to the connection exactly what a bad network does:
 *
 *  - RST the socket the instant the query goes out (connection reset mid-flight)
 *  - accept the connection and never answer (does `_withTimeout` actually fire?)
 *  - answer correctly, but 1.5s after the engine gave up (is the LATE response used?)
 *  - break one half of a split adapter (roles load, policies do not - and back)
 *  - exhaust the connection pool
 *  - oversize the role and policy sets
 *
 * The invariant is the same one: a system that cannot answer must DENY, and
 * the recorded verdict is the value the CALLER received.
 *
 * Owns its own container on a fixed free port, unlabelled, so the shared e2e
 * Postgres is never touched.
 */
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

const PG_IMAGE = 'postgres:16-alpine'
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
 *
 * `pass` forwards both directions untouched. `blackhole` accepts and forwards
 * nothing, so the peer waits forever - the only honest way to ask whether the
 * engine's own timeout fires. `delayMs` holds server->client bytes, so a
 * response can be made to land *after* the engine has already given up.
 * `killNow()` RSTs every live pair.
 */
class FaultProxy {
  mode: 'pass' | 'blackhole' = 'pass'
  /** Milliseconds to hold each server->client chunk. */
  delayMs = 0
  /** When set, the next client->server chunk RSTs the pair instead of being forwarded. */
  resetOnNextQuery = false
  /** Refuse new connections outright (listener closed) while true. */
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
      // `resetAndDestroy` sends RST rather than FIN, which is the difference
      // between "server closed politely" and "the network ate it".
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
  // pg raises `error` on the Pool when an idle socket dies; unhandled it kills
  // the worker. That is a pg property, not a duck-iam verdict.
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
 * The healthy-path baseline a fault test takes before arming its fault.
 *
 * Retries instead of asserting once, because the pool is shared across this
 * file and carries the previous test's damage: a connection an earlier test
 * RST at the socket can still be sitting in `pg`'s idle set, and the first
 * acquire after that gets the dead client back and denies in single-digit
 * milliseconds. That deny is correct - the system could not answer, so it
 * refused - but it belongs to the previous test's fault, not the one this test
 * is about to arm, and asserting on it measures nothing.
 *
 * The retry is bounded and still an assertion. A reset that left the pool
 * permanently unable to answer would be a real bug - a transient network fault
 * turned into a standing denial of service - and this goes red for it.
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

/**
 * A real drizzle adapter whose four read methods can each be pointed at a
 * SECOND real drizzle adapter on a different (breakable) connection. Nothing is
 * stubbed: both halves talk to the same Postgres, one of them through a proxy
 * that can be made to fail. That is what makes "roles load but policies do not"
 * a real partial failure rather than a mock throwing on cue.
 */
type ReadMethod = 'listPolicies' | 'listRoles' | 'getSubjectRoles' | 'getSubjectAttributes'

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
    // A reset is an immediate error, not a timeout: it must not cost the full
    // adapter timeout, and it certainly must not hang.
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
    // The whole point of the timeout: it has to actually fire. Generous bound
    // so this is a liveness assertion, not a latency one.
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
    // Long TTL on purpose: if the late load lands in the cache, the NEXT check
    // can be answered from it - which is the fail-open this test hunts.
    const engine = engineOn(adapterOn(proxyPool), { adapterTimeoutMs: 700, cacheTTL: 60 })

    // Hold every response for well past the timeout. Nothing is cached yet.
    proxy.delayMs = 2000
    const t0 = Date.now()
    const first = await engine.can('u1', 'read', DOC)
    const elapsed = Date.now() - t0
    expect(first, 'a response that arrived after the timeout must not answer').toBe(false)
    expect(elapsed).toBeLessThan(2000)

    // Let the late response land, then make the backend unable to answer at
    // all. If the next check allows, it can only have come from the late
    // response having been written into the cache.
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

      // Everything healthy: the fixture allows. This is what makes the deny
      // below attributable to the partial failure and nothing else.
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

    // The subject still resolves (assignments + attrs are on the healthy half);
    // only the policy load is gone.
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
  /**
   * >32 roles puts the engine on the interpreter (the compiled table cannot
   * address a 33rd role). That is a second code path, and it has to fail closed
   * for the same reasons. Runs in its own database so the role explosion cannot
   * leak into the suites above.
   */
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
