/**
 * E2E: a revoke must stop being honoured everywhere, over real Redis and Postgres, including across two OS processes.
 * `cacheTTL` is 600s, so convergence here can only come from invalidation, never expiry.
 */
import { spawn } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { join } from 'node:path'
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { IamEngine } from '../../../core/engine/engine'
import type { IamRequest } from '../../../core/types'
import { applyPgSchema } from '../../../test/e2e-env'
import { createIamRedisInvalidator } from '../index'
import {
  dockerAvailable,
  pubSubOver,
  RedisConn,
  removeContainer,
  startPostgres,
  startRedis,
  waitFor,
} from './e2e-invalidation-redis'

const HAS_DOCKER = await dockerAvailable()

const OPS = { and, eq, or }
const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }

type Action = 'read'
type Res = 'post'
type Role = 'admin'

const SECRET = 'e2e-shared-secret'

/**
 * Re-signs a captured envelope for another channel with the shared secret, for the reordering test.
 * Forgery without the secret is covered in `e2e-invalidation-failure-modes.e2e.test.ts`.
 */
function resignFor(raw: string, channel: string): string {
  const canonical = (v: unknown): string => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v)
    if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(Reflect.get(v, k))}`)
      .join(',')}}`
  }
  const parsed: unknown = JSON.parse(raw)
  if (parsed === null || typeof parsed !== 'object') throw new Error(`captured envelope is not an object: ${raw}`)
  const payload: unknown = Reflect.get(parsed, 'payload')
  if (payload === null || typeof payload !== 'object') throw new Error(`captured envelope has no payload: ${raw}`)
  const rebound = { ...payload, channel }
  const sig = createHmac('sha256', SECRET)
    .update(canonical(JSON.parse(JSON.stringify(rebound))))
    .digest('hex')
  return JSON.stringify({ payload: rebound, sig, v: 2 })
}
/** Long enough that no TTL expiry can be mistaken for a working invalidation. */
const LONG_TTL_SECONDS = 600
/** Generous ceiling: a local docker Redis round-trip is sub-millisecond. */
const CONVERGE_MS = 3_000
const READ_POST: IamRequest.IResource<Res> = { attributes: {}, type: 'post' }

interface Instance {
  engine: IamEngine<Action, Res, Role, string, 'production' | 'development'>
  pub: RedisConn
  sub: RedisConn
  close(): Promise<void>
}

const suite = HAS_DOCKER ? describe : describe.skip

// Guard against a silent skip: CI requires docker, and locally a running docker must not leave the suite gated off.
describe('E2E reachability (invalidation: cross-instance)', () => {
  it('does not skip while docker is available', () => {
    if (process.env.CI) {
      expect(HAS_DOCKER, 'docker is unavailable in CI, where the workflow provides it').toBe(true)
    }
    if (HAS_DOCKER) expect(suite, 'docker is up but the suite is gated off anyway').toBe(describe)
  })
})

suite('E2E cross-instance invalidation over real Redis + Postgres', () => {
  let redisName = ''
  let pgName = ''
  let redisPort = 0
  let pgUrl = ''
  let adminPool: Pool
  const open: Instance[] = []
  const spare: RedisConn[] = []

  async function makeInstance(opts: {
    channel: string
    mode?: 'production' | 'development'
    cacheTTL?: number
  }): Promise<Instance> {
    const pool = new Pool({ connectionString: pgUrl, max: 4 })
    const db = drizzle(pool)
    const pub = await RedisConn.open(redisPort)
    const sub = await RedisConn.open(redisPort)
    const engine = new IamEngine<Action, Res, Role, string, 'production' | 'development'>({
      adapter: new IamDrizzleAdapter<Action, Res, Role, string>({ db, ops: OPS, tables: TABLES }),
      cacheTTL: opts.cacheTTL ?? LONG_TTL_SECONDS,
      invalidator: createIamRedisInvalidator<Role>({
        channel: opts.channel,
        client: pubSubOver(pub, sub),
        secret: SECRET,
      }),
      mode: opts.mode ?? 'production',
    })
    const inst: Instance = {
      async close() {
        engine.dispose()
        pub.close()
        sub.close()
        await pool.end().catch(() => {})
      },
      engine,
      pub,
      sub,
    }
    open.push(inst)
    // `subscribe()` is fire-and-forget; wait until Redis reports the subscriber so an early publish is not lost.
    const ready = await waitFor(async () => {
      const r = await pub.command('PUBSUB', 'NUMSUB', opts.channel)
      return Array.isArray(r) && Number(r[1]) >= 1
    }, 10_000)
    if (ready === null) throw new Error(`[e2e-invalidation] instance never subscribed to ${opts.channel}`)
    return inst
  }

  beforeAll(async () => {
    if (!HAS_DOCKER) throw new Error('[e2e-invalidation] docker unavailable; this suite requires it')
    const [redis, pg] = await Promise.all([startRedis(), startPostgres()])
    redisName = redis.name
    redisPort = redis.port
    pgName = pg.name
    pgUrl = pg.url
    adminPool = new Pool({ connectionString: pgUrl })
    await applyPgSchema(adminPool)
  }, 180_000)

  afterAll(async () => {
    for (const i of open.splice(0, open.length)) await i.close().catch(() => {})
    for (const c of spare.splice(0, spare.length)) c.close()
    await adminPool?.end().catch(() => {})
    if (redisName) await removeContainer(redisName)
    if (pgName) await removeContainer(pgName)
  }, 60_000)

  beforeEach(async () => {
    for (const i of open.splice(0, open.length)) await i.close().catch(() => {})
    for (const c of spare.splice(0, spare.length)) c.close()
    await adminPool.query('TRUNCATE iam_assignments, iam_subject_attrs, iam_roles, iam_policies CASCADE')
  })

  let channelSeq = 0
  function channel(name: string): string {
    channelSeq++
    return `e2e-inv-cross:${name}:${channelSeq}`
  }

  async function seedAdminRole(inst: Instance): Promise<void> {
    await inst.engine.admin.saveRole({
      id: 'admin',
      name: 'admin',
      permissions: [{ action: 'read', resource: 'post' }],
    })
  }

  it('a revoke on A stops being honoured on B, and invalidation not TTL is what does it', async () => {
    const ch = channel('revoke')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('u1', 'admin')

    // Warm B so it holds a cached allow. That is the state that matters.
    expect(await b.engine.can('u1', 'read', READ_POST)).toBe(true)

    const t0 = Date.now()
    await a.engine.admin.revokeRole('u1', 'admin')

    const elapsed = await waitFor(async () => (await b.engine.can('u1', 'read', READ_POST)) === false, CONVERGE_MS)
    const total = Date.now() - t0
    // With a 600s TTL, convergence within seconds can only be the invalidation message.
    expect(elapsed, `B still allowed ${total}ms after the revoke (cacheTTL=${LONG_TTL_SECONDS}s)`).not.toBeNull()
    console.info(`[measure] revoke on A -> deny on B in ${total}ms (TTL ${LONG_TTL_SECONDS}s)`)
  }, 60_000)

  it('a grant on A becomes visible on B (positive control for the same channel)', async () => {
    const ch = channel('grant')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })

    await seedAdminRole(a)
    expect(await b.engine.can('u2', 'read', READ_POST)).toBe(false)

    await a.engine.admin.assignRole('u2', 'admin')
    const elapsed = await waitFor(async () => (await b.engine.can('u2', 'read', READ_POST)) === true, CONVERGE_MS)
    expect(elapsed, 'B never saw the grant').not.toBeNull()
  }, 60_000)

  it('a role permission change on A reaches the compiled table of BOTH a production and a development B', async () => {
    const ch = channel('table')
    const a = await makeInstance({ channel: ch })
    const prod = await makeInstance({ channel: ch, mode: 'production' })
    const dev = await makeInstance({ channel: ch, mode: 'development' })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('u3', 'admin')

    // Both modes evaluate through a compiled table. Warm both.
    expect(await prod.engine.can('u3', 'read', READ_POST)).toBe(true)
    expect(await dev.engine.can('u3', 'read', READ_POST)).toBe(true)

    // Strip the permission from the role itself. This grant lives only in the
    // compiled table - no subject cache entry changes.
    await a.engine.admin.saveRole({ id: 'admin', name: 'admin', permissions: [] })

    const prodMs = await waitFor(async () => (await prod.engine.can('u3', 'read', READ_POST)) === false, CONVERGE_MS)
    const devMs = await waitFor(async () => (await dev.engine.can('u3', 'read', READ_POST)) === false, CONVERGE_MS)
    expect(prodMs, 'production instance kept a stale compiled table').not.toBeNull()
    expect(devMs, 'development instance kept a stale compiled table').not.toBeNull()
    console.info(`[measure] role-permission revoke reached compiled table: prod ${prodMs}ms, dev ${devMs}ms`)
  }, 60_000)

  it('a policy change on A reaches B (policies event clears the compiled table too)', async () => {
    const ch = channel('policy')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('u6', 'admin')
    expect(await b.engine.can('u6', 'read', READ_POST)).toBe(true)

    // A deny policy added on A must stop B allowing.
    await a.engine.admin.savePolicy({
      id: 'p-deny-read',
      name: 'deny read',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r1', effect: 'deny', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
      ],
    })

    const ms = await waitFor(async () => (await b.engine.can('u6', 'read', READ_POST)) === false, CONVERGE_MS)
    expect(ms, 'B kept allowing after a deny policy was created on A').not.toBeNull()
    console.info(`[measure] deny-policy create on A -> deny on B in ${ms}ms`)
  }, 60_000)

  it('deleting a role on A denies on B even though the event carries only the role id', async () => {
    const ch = channel('delrole')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('u4', 'admin')
    expect(await b.engine.can('u4', 'read', READ_POST)).toBe(true)

    await a.engine.admin.deleteRole('admin')
    const ms = await waitFor(async () => (await b.engine.can('u4', 'read', READ_POST)) === false, CONVERGE_MS)
    expect(ms, 'B honoured a deleted role').not.toBeNull()
  }, 60_000)

  it('revoke -> grant -> revoke delivered in REVERSE order still converges to deny', async () => {
    // A publishes on its own channel; a spy re-signs its three envelopes for B's channel and replays them backwards.
    // Redis never reorders within a connection, so the reordering has to be forced.
    const chA = channel('order-a')
    const chB = channel('order-b')
    const a = await makeInstance({ channel: chA })
    const b = await makeInstance({ channel: chB })

    const spy = await RedisConn.open(redisPort)
    spare.push(spy)
    const captured: string[] = []
    await spy.subscribeChannel(chA, (m) => captured.push(m))

    await seedAdminRole(a)
    await a.engine.admin.assignRole('u5', 'admin')
    expect(await b.engine.can('u5', 'read', READ_POST)).toBe(true)

    captured.length = 0
    await a.engine.admin.revokeRole('u5', 'admin')
    await a.engine.admin.assignRole('u5', 'admin')
    await a.engine.admin.revokeRole('u5', 'admin')
    const got = await waitFor(() => captured.length >= 3, 5_000)
    expect(got, `only ${captured.length} envelopes captured`).not.toBeNull()

    for (const raw of [...captured].reverse()) await a.pub.command('PUBLISH', chB, resignFor(raw, chB))

    // The DB says "no role", so the only correct converged answer is deny.
    const ms = await waitFor(async () => (await b.engine.can('u5', 'read', READ_POST)) === false, CONVERGE_MS)
    expect(ms, 'B converged to ALLOW after out-of-order revoke/grant/revoke').not.toBeNull()
  }, 60_000)

  it('two instances writing concurrently through the admin API converge to the DB answer', async () => {
    const ch = channel('concurrent')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })
    await seedAdminRole(a)

    for (let i = 0; i < 8; i++) {
      const subject = `race-${i}`
      await Promise.all([a.engine.admin.assignRole(subject, 'admin'), b.engine.admin.revokeRole(subject, 'admin')])

      const rows = await adminPool.query('SELECT count(*)::int AS n FROM iam_assignments WHERE subject_id = $1', [
        subject,
      ])
      const inDb = (rows.rows[0] as { n: number }).n > 0

      const converged = await waitFor(async () => {
        const [ra, rb] = await Promise.all([
          a.engine.can(subject, 'read', READ_POST),
          b.engine.can(subject, 'read', READ_POST),
        ])
        return ra === inDb && rb === inDb
      }, CONVERGE_MS)
      expect(converged, `round ${i}: an engine disagreed with the DB (db says ${String(inDb)})`).not.toBeNull()
    }
  }, 180_000)

  it('a revoke landing mid-flight on B never writes the stale subject back into the cache', async () => {
    const ch = channel('inflight')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })
    await seedAdminRole(a)

    for (let i = 0; i < 12; i++) {
      const subject = `flight-${i}`
      await a.engine.admin.assignRole(subject, 'admin')
      // Cold on B: this starts an adapter load for `subject`.
      const inFlight = b.engine.can(subject, 'read', READ_POST)
      // Revoke while that load is still resolving.
      await a.engine.admin.revokeRole(subject, 'admin')
      await inFlight

      const ms = await waitFor(async () => (await b.engine.can(subject, 'read', READ_POST)) === false, CONVERGE_MS)
      expect(ms, `round ${i}: B kept a stale allow written back by an in-flight load`).not.toBeNull()
    }
  }, 180_000)

  it('TWO REAL PROCESSES: a revoke here is honoured over there until the message lands, then never again', async () => {
    // The second engine runs under its own `bun`, with a separate heap and event loop.
    const ch = channel('twoproc')
    const a = await makeInstance({ channel: ch })
    await seedAdminRole(a)

    const worker = spawn('bun', [join(import.meta.dirname, 'e2e-invalidation-worker.ts')], {
      env: {
        ...process.env,
        CHANNEL: ch,
        PG_URL: pgUrl,
        REDIS_PORT: String(redisPort),
        SECRET,
        TTL_SECONDS: String(LONG_TTL_SECONDS),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const stderr: string[] = []
    worker.stderr.setEncoding('utf8')
    worker.stderr.on('data', (c: string) => stderr.push(c))

    const inbox: Array<Record<string, unknown>> = []
    let buffer = ''
    worker.stdout.setEncoding('utf8')
    worker.stdout.on('data', (chunk: string) => {
      buffer += chunk
      for (;;) {
        const nl = buffer.indexOf('\n')
        if (nl < 0) return
        const line = buffer.slice(0, nl).trim()
        buffer = buffer.slice(nl + 1)
        if (line.length > 0) inbox.push(JSON.parse(line) as Record<string, unknown>)
      }
    })

    let seq = 0
    async function ask(cmd: string, subject?: string): Promise<Record<string, unknown>> {
      seq++
      const id = seq
      worker.stdin.write(`${JSON.stringify({ cmd, id, subject })}\n`)
      const got = await waitFor(() => inbox.some((m) => m.id === id), 20_000)
      if (got === null) throw new Error(`worker never answered ${cmd} (stderr: ${stderr.join('')})`)
      const reply = inbox.find((m) => m.id === id)
      if (reply === undefined) throw new Error('unreachable')
      if (reply.error !== undefined) throw new Error(String(reply.error))
      return reply
    }

    try {
      const booted = await waitFor(() => inbox.some((m) => m.ready === true), 60_000)
      if (booted === null) throw new Error(`worker never booted (stderr: ${stderr.join('')})`)

      await a.engine.admin.assignRole('p1', 'admin')
      // Settle and read twice: a load superseded mid-flight is not cached, and an uncached read converges trivially.
      await new Promise((r) => setTimeout(r, 250))
      expect((await ask('can', 'p1')).allowed).toBe(true)
      expect((await ask('can', 'p1')).allowed).toBe(true)

      const t0 = Date.now()
      await a.engine.admin.revokeRole('p1', 'admin')
      const converged = await waitFor(async () => (await ask('can', 'p1')).allowed === false, CONVERGE_MS)
      expect(converged, `the other process still allowed ${Date.now() - t0}ms after the revoke`).not.toBeNull()
      console.info(`[measure] TWO PROCESSES: revoke here -> deny there in ${Date.now() - t0}ms`)

      // And the reverse direction: the worker revokes, this process must follow.
      await a.engine.admin.assignRole('p2', 'admin')
      await new Promise((r) => setTimeout(r, 250))
      expect(await a.engine.can('p2', 'read', READ_POST)).toBe(true)
      await ask('revoke', 'p2')
      const back = await waitFor(async () => (await a.engine.can('p2', 'read', READ_POST)) === false, CONVERGE_MS)
      expect(back, 'this process kept honouring a grant the other process revoked').not.toBeNull()
      console.info(`[measure] TWO PROCESSES: revoke there -> deny here in ${back}ms`)
    } finally {
      worker.stdin.write(`${JSON.stringify({ cmd: 'exit', id: 999 })}\n`)
      await waitFor(() => worker.exitCode !== null, 5_000)
      worker.kill('SIGKILL')
    }
  }, 180_000)

  it('tenant channels isolate: a tenant-B broadcast does not wipe tenant A', async () => {
    const base = channel('tenant')
    const pub = await RedisConn.open(redisPort)
    const sub = await RedisConn.open(redisPort)
    const otherSub = await RedisConn.open(redisPort)
    spare.push(pub, sub, otherSub)

    const seen: string[] = []
    const t1 = createIamRedisInvalidator<Role>({
      channel: base,
      client: pubSubOver(pub, sub),
      secret: SECRET,
      tenantId: 't1',
    })
    const unsub = t1.subscribe((e) => seen.push(e.kind))
    const ready = await waitFor(async () => {
      const r = await pub.command('PUBSUB', 'NUMSUB', `${base}:tenant:t1`)
      return Array.isArray(r) && Number(r[1]) >= 1
    }, 10_000)
    expect(ready).not.toBeNull()

    const t2 = createIamRedisInvalidator<Role>({
      channel: base,
      client: pubSubOver(pub, otherSub),
      secret: SECRET,
      tenantId: 't2',
    })
    t2.publish({ kind: 'all' })
    await new Promise((r) => setTimeout(r, 300))
    expect(seen, 'a tenant-t2 broadcast reached tenant t1').toEqual([])
    unsub()
  }, 60_000)
})
