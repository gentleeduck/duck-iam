/**
 * E2E: what a second instance does when invalidation does NOT arrive.
 *
 * The happy path is covered by `e2e-invalidation-cross-instance.e2e.test.ts`.
 * This suite is the other half, and it is the half that decides severity: a
 * revoked grant that keeps being honoured is only acceptable if something
 * bounds how long, and only diagnosable if something says so.
 *
 * Every case here manufactures a real delivery failure against a real Redis -
 * a server-side `CLIENT KILL`, a rejecting `subscribe()`, a fleet where half
 * the nodes hold the HMAC secret and half do not - and then measures how long
 * the stale allow survives.
 *
 * Cases that assert "B still allows" are also the negative control for the
 * whole exercise: they are what proves the passing convergence tests next door
 * are measuring invalidation rather than passing by construction.
 */
import { createHmac } from 'node:crypto'
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { IamEngine } from '../../../core/engine/engine'
import type { IamRequest } from '../../../core/types'
import { applyPgSchema } from '../../../test/e2e-env'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'
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
const LONG_TTL_SECONDS = 600
const SHORT_TTL_SECONDS = 1
const READ_POST: IamRequest.IResource<Res> = { attributes: {}, type: 'post' }
/** How long a stale allow is observed before it is declared to be surviving. */
const STALENESS_WINDOW_MS = 1_500

interface Instance {
  engine: IamEngine<Action, Res, Role, string, 'production'>
  pub: RedisConn
  sub: RedisConn
  /**
   * `can()` swallows adapter errors and returns `false` (correctly - fail
   * closed). That makes a bare `false` ambiguous in a staleness test: it could
   * be convergence, or it could be a transient Postgres blip. Every instance
   * records its errors so a measurement taken over an error is rejected rather
   * than reported.
   */
  errors: Error[]
  close(): Promise<void>
}

const suite = HAS_DOCKER ? describe : describe.skip

suite('E2E invalidation failure modes (real Redis, real Postgres)', () => {
  let redisName = ''
  let pgName = ''
  let redisPort = 0
  let pgUrl = ''
  let adminPool: Pool
  const open: Instance[] = []
  const spare: RedisConn[] = []

  async function makeInstance(opts: {
    channel: string
    cacheTTL?: number
    secret?: string | null
    onSubscribeError?: (err: Error, channel: string) => void
    /** Replace the pub/sub client entirely (used for the rejecting-subscribe case). */
    client?: IamRedisInvalidator.IPubSubLike
    waitForSubscriber?: boolean
  }): Promise<Instance> {
    const pool = new Pool({ connectionString: pgUrl, max: 4 })
    const db = drizzle(pool)
    const pub = await RedisConn.open(redisPort)
    const sub = await RedisConn.open(redisPort)
    const errors: Error[] = []
    const engine = new IamEngine<Action, Res, Role, string, 'production'>({
      adapter: new IamDrizzleAdapter<Action, Res, Role, string>({ db, ops: OPS, tables: TABLES }),
      cacheTTL: opts.cacheTTL ?? LONG_TTL_SECONDS,
      hooks: {
        onError: (err) => {
          errors.push(err)
        },
      },
      invalidator: createIamRedisInvalidator<Role>({
        channel: opts.channel,
        client: opts.client ?? pubSubOver(pub, sub),
        secret: opts.secret === undefined ? SECRET : opts.secret,
        ...(opts.onSubscribeError ? { onSubscribeError: opts.onSubscribeError } : {}),
      }),
      mode: 'production',
    })
    const inst: Instance = {
      async close() {
        engine.dispose()
        pub.close()
        sub.close()
        await pool.end().catch(() => {})
      },
      engine,
      errors,
      pub,
      sub,
    }
    open.push(inst)
    if (opts.waitForSubscriber !== false) {
      const ready = await waitFor(async () => {
        const r = await pub.command('PUBSUB', 'NUMSUB', opts.channel)
        return Array.isArray(r) && Number(r[1]) >= 1
      }, 10_000)
      if (ready === null) throw new Error(`[e2e-invalidation] instance never subscribed to ${opts.channel}`)
    }
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
    return `e2e-inv-fail:${name}:${channelSeq}`
  }

  async function seedAdminRole(inst: Instance): Promise<void> {
    await inst.engine.admin.saveRole({
      id: 'admin',
      name: 'admin',
      permissions: [{ action: 'read', resource: 'post' }],
    })
  }

  /**
   * Warm `inst`'s caches for `subjectId` and prove the entry actually landed.
   *
   * Not ceremony. `resolveSubject` deliberately refuses to cache a load that an
   * invalidation superseded mid-flight (`runSingleFlightKeyed` only writes back
   * when the in-flight slot still holds its own promise), so a `can()` issued
   * immediately after the grant that caused the broadcast frequently leaves the
   * cache EMPTY. A staleness test warmed that way measures nothing: the node
   * re-reads Postgres on every call and "converges" instantly for the wrong
   * reason. Settling first, then reading twice, makes the warm state real.
   */
  async function warm(inst: Instance, subjectId: string, expected: boolean): Promise<void> {
    await new Promise((r) => setTimeout(r, 250))
    expect(await inst.engine.can(subjectId, 'read', READ_POST)).toBe(expected)
    expect(await inst.engine.can(subjectId, 'read', READ_POST)).toBe(expected)
  }

  /** Remove the grant with raw SQL, so NO invalidation is published anywhere. */
  async function silentlyRevoke(subjectId: string): Promise<void> {
    await adminPool.query('DELETE FROM iam_assignments WHERE subject_id = $1', [subjectId])
  }

  // ── delivery loss ────────────────────────────────────────────────────────

  it('NEGATIVE CONTROL: with the subscriber killed server-side, a revoke on A is honoured indefinitely on B', async () => {
    const ch = channel('killed')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('k1', 'admin')
    await warm(b, 'k1', true)

    // Exactly what a redis restart, a failover, or `CLIENT KILL` maintenance
    // does to a subscriber. B's invalidator has already latched `subscribed`.
    await a.pub.command('CLIENT', 'KILL', 'TYPE', 'pubsub')
    const closedMs = await waitFor(() => b.sub.closed, 5_000)
    expect(closedMs, 'the subscriber connection was never actually killed').not.toBeNull()

    await a.engine.admin.revokeRole('k1', 'admin')

    const converged = await waitFor(
      async () => (await b.engine.can('k1', 'read', READ_POST)) === false,
      STALENESS_WINDOW_MS,
    )
    // If this ever starts passing (i.e. `converged !== null`), the product grew
    // a resubscribe or a heartbeat and this test should be re-read, not deleted.
    expect(
      b.errors.map((e) => e.message),
      'B hit adapter errors; the deny below would be fail-closed, not convergence',
    ).toEqual([])
    expect(converged, 'B converged despite a dead subscriber - re-read this test, the product changed').toBeNull()
    expect(await b.engine.can('k1', 'read', READ_POST)).toBe(true)
    console.info(
      `[measure] subscriber killed: B still honours the revoked grant after ${STALENESS_WINDOW_MS}ms; TTL is ${LONG_TTL_SECONDS}s`,
    )
  }, 60_000)

  it('the invalidator never resubscribes after the connection comes back - deafness is permanent', async () => {
    const ch = channel('noresub')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('k2', 'admin')
    await warm(b, 'k2', true)

    await a.pub.command('CLIENT', 'KILL', 'TYPE', 'pubsub')
    const closed = await waitFor(() => b.sub.closed, 5_000)
    expect(closed, 'the subscriber connection was never actually killed').not.toBeNull()

    // Redis is healthy again immediately - the server never went away. Give the
    // invalidator every chance: further admin writes, further reads on B.
    await a.engine.admin.revokeRole('k2', 'admin')
    for (let i = 0; i < 5; i++) {
      await a.engine.admin.assignRole(`noise-${i}`, 'admin')
      await b.engine.can(`noise-${i}`, 'read', READ_POST)
      await new Promise((r) => setTimeout(r, 100))
    }

    // Nothing re-issued SUBSCRIBE: the server reports no subscriber.
    const numsub = await a.pub.command('PUBSUB', 'NUMSUB', ch)
    expect(Array.isArray(numsub) ? Number(numsub[1]) : -1, 'a subscriber came back').toBe(0)
    expect(
      b.errors.map((e) => e.message),
      'B hit adapter errors; a deny would be fail-closed, not convergence',
    ).toEqual([])
    expect(await b.engine.can('k2', 'read', READ_POST), 'B stopped honouring the revoked grant').toBe(true)
  }, 60_000)

  it('TTL is the only backstop, and it does cover subject, role and policy caches AND the compiled table', async () => {
    const ch = channel('ttl')
    const a = await makeInstance({ channel: ch })
    const b = await makeInstance({ channel: ch, cacheTTL: SHORT_TTL_SECONDS })

    await seedAdminRole(a)
    await a.engine.admin.assignRole('t1', 'admin')
    await warm(b, 't1', true)

    // Cut delivery, then make three different kinds of change.
    await a.pub.command('CLIENT', 'KILL', 'TYPE', 'pubsub')
    await waitFor(() => b.sub.closed, 2_000)

    // (1) subject cache: revoke the assignment.
    await a.engine.admin.revokeRole('t1', 'admin')
    const subjectMs = await waitFor(async () => (await b.engine.can('t1', 'read', READ_POST)) === false, 10_000)
    expect(subjectMs, 'subject cache never expired').not.toBeNull()

    // (2) role cache + compiled table: put the grant back, then empty the role.
    await a.engine.admin.assignRole('t2', 'admin')
    await waitFor(async () => (await b.engine.can('t2', 'read', READ_POST)) === true, 10_000)
    await a.engine.admin.saveRole({ id: 'admin', name: 'admin', permissions: [] })
    const tableMs = await waitFor(async () => (await b.engine.can('t2', 'read', READ_POST)) === false, 10_000)
    expect(tableMs, 'compiled table never expired - stale allow outlives its TTL').not.toBeNull()

    console.info(
      `[measure] TTL=${SHORT_TTL_SECONDS}s backstop: subject cache ${subjectMs}ms, compiled table ${tableMs}ms`,
    )
    // A TTL backstop that takes much longer than the TTL is a finding in itself.
    expect(subjectMs).toBeLessThan(SHORT_TTL_SECONDS * 1000 * 4)
    expect(tableMs).toBeLessThan(SHORT_TTL_SECONDS * 1000 * 4)
  }, 90_000)

  // ── subscribe failure ────────────────────────────────────────────────────

  it('a rejecting subscribe() reports once and is never retried; the node is deaf for its whole life', async () => {
    const ch = channel('subfail')
    const a = await makeInstance({ channel: ch })

    let subscribeCalls = 0
    const errors: string[] = []
    const brokenClient: IamRedisInvalidator.IPubSubLike = {
      publish() {
        return undefined
      },
      subscribe() {
        subscribeCalls++
        return Promise.reject(new Error('NOAUTH Authentication required.'))
      },
    }
    const b = await makeInstance({
      channel: ch,
      client: brokenClient,
      onSubscribeError: (err) => errors.push(err.message),
      waitForSubscriber: false,
    })

    await waitFor(() => errors.length > 0, 5_000)
    expect(errors, 'onSubscribeError never fired for a rejected subscribe').toEqual(['NOAUTH Authentication required.'])

    await seedAdminRole(a)
    await a.engine.admin.assignRole('s1', 'admin')
    await warm(b, 's1', true)
    await a.engine.admin.revokeRole('s1', 'admin')

    const converged = await waitFor(
      async () => (await b.engine.can('s1', 'read', READ_POST)) === false,
      STALENESS_WINDOW_MS,
    )
    expect(
      b.errors.map((e) => e.message),
      'B hit adapter errors during the staleness window',
    ).toEqual([])
    expect(converged, 'a node whose subscribe failed somehow converged').toBeNull()
    // One attempt. Nothing in the engine or the invalidator retries it.
    expect(subscribeCalls, 'subscribe was retried').toBe(1)

    // And the node reports itself healthy while permanently deaf.
    const health = await b.engine.healthCheck()
    expect(health.ok, 'healthCheck already knows about the dead subscription').toBe(true)
  }, 60_000)

  it('recovery after a kill is entirely the client library job - a self-resubscribing client converges again', async () => {
    // Scope for the finding above: the invalidator latches `subscribed` and
    // never re-issues SUBSCRIBE, so whether a node comes back depends on
    // whether the redis client resubscribes on reconnect (ioredis and
    // node-redis v4 do). Modelled here, the node recovers. Wired to a client
    // that does not, it stays deaf - and nothing in duck-iam notices either way.
    const ch = channel('resub')
    const a = await makeInstance({ channel: ch })

    let live = await RedisConn.open(redisPort)
    spare.push(live)
    let handler: ((m: string) => void) | null = null
    let resubscribes = 0
    const reconnecting: IamRedisInvalidator.IPubSubLike = {
      publish(c, m) {
        return live.command('PUBLISH', c, m)
      },
      async subscribe(c, h) {
        handler = h
        await live.subscribeChannel(c, h)
        const watch = setInterval(() => {
          if (!live.closed || handler === null) return
          clearInterval(watch)
          void (async () => {
            const fresh = await RedisConn.open(redisPort)
            spare.push(fresh)
            live = fresh
            resubscribes++
            if (handler) await fresh.subscribeChannel(c, handler)
          })()
        }, 20)
        watch.unref?.()
      },
    }

    const b = await makeInstance({ channel: ch, client: reconnecting, waitForSubscriber: false })
    const up = await waitFor(async () => {
      const r = await a.pub.command('PUBSUB', 'NUMSUB', ch)
      return Array.isArray(r) && Number(r[1]) >= 1
    }, 10_000)
    expect(up).not.toBeNull()

    await seedAdminRole(a)
    await a.engine.admin.assignRole('r1', 'admin')
    await warm(b, 'r1', true)

    await a.pub.command('CLIENT', 'KILL', 'TYPE', 'pubsub')
    const back = await waitFor(() => resubscribes > 0, 10_000)
    expect(back, 'the modelled client never resubscribed').not.toBeNull()
    await waitFor(async () => {
      const r = await a.pub.command('PUBSUB', 'NUMSUB', ch)
      return Array.isArray(r) && Number(r[1]) >= 1
    }, 10_000)

    await a.engine.admin.revokeRole('r1', 'admin')
    const ms = await waitFor(async () => (await b.engine.can('r1', 'read', READ_POST)) === false, 5_000)
    expect(b.errors.map((e) => e.message)).toEqual([])
    expect(ms, 'delivery did not resume even though the client resubscribed').not.toBeNull()
    console.info(`[measure] client-driven resubscribe restored delivery; converged in ${ms}ms`)
  }, 90_000)

  // ── fleet misconfiguration ───────────────────────────────────────────────

  it('a half-rolled-out secret splits the fleet: the signed node and the unsigned node never hear each other', async () => {
    const ch = channel('mixedsecret')
    const signed = await makeInstance({ channel: ch, secret: SECRET })
    const unsigned = await makeInstance({ channel: ch, secret: null })

    await seedAdminRole(signed)
    await signed.engine.admin.assignRole('m1', 'admin')
    await unsigned.engine.admin.assignRole('m2', 'admin')
    await warm(unsigned, 'm1', true)
    await warm(signed, 'm2', true)

    await signed.engine.admin.revokeRole('m1', 'admin')
    await unsigned.engine.admin.revokeRole('m2', 'admin')

    const unsignedSaw = await waitFor(
      async () => (await unsigned.engine.can('m1', 'read', READ_POST)) === false,
      STALENESS_WINDOW_MS,
    )
    const signedSaw = await waitFor(
      async () => (await signed.engine.can('m2', 'read', READ_POST)) === false,
      STALENESS_WINDOW_MS,
    )
    // Both directions are dropped: the unsigned node refuses v:1 envelopes, and
    // the signed node refuses legacy ones.
    expect(unsigned.errors.map((e) => e.message)).toEqual([])
    expect(signed.errors.map((e) => e.message)).toEqual([])
    expect(unsignedSaw, 'unsigned node accepted a v:1 envelope it cannot verify').toBeNull()
    expect(signedSaw, 'signed node accepted an unsigned envelope').toBeNull()
    console.info('[measure] mixed-secret fleet: neither direction converged within 1500ms; TTL is the only backstop')
  }, 60_000)

  // ── forged and replayed messages ─────────────────────────────────────────

  /**
   * Warm B with an allow, then remove the grant with raw SQL so no invalidation
   * is published. B keeps saying allow until *something* clears its cache. Any
   * message that flips B to deny was accepted; any that leaves it on allow was
   * dropped. That makes acceptance directly observable.
   */
  async function armForgeryProbe(subjectId: string, ch: string): Promise<{ a: Instance; b: Instance }> {
    const a = await makeInstance({ channel: `${ch}-writer` })
    const b = await makeInstance({ channel: ch })
    await seedAdminRole(a)
    await a.engine.admin.assignRole(subjectId, 'admin')
    await warm(b, subjectId, true)
    await silentlyRevoke(subjectId)
    expect(await b.engine.can(subjectId, 'read', READ_POST), 'probe not armed').toBe(true)
    return { a, b }
  }

  function sign(payload: unknown): string {
    // Mirrors the publisher's pre-image: canonical JSON of the round-tripped value.
    const canonical = (v: unknown): string => {
      if (v === null || typeof v !== 'object') return JSON.stringify(v)
      if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
      const keys = Object.keys(v).sort()
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(Reflect.get(v, k))}`).join(',')}}`
    }
    return createHmac('sha256', SECRET)
      .update(canonical(JSON.parse(JSON.stringify(payload))))
      .digest('hex')
  }

  it('a signed node drops forged and replayed envelopes, and accepts a correctly signed one', async () => {
    const ch = channel('forge')
    const { a, b } = await armForgeryProbe('f1', ch)

    // 1. Garbage.
    await a.pub.command('PUBLISH', ch, 'not json at all')
    // 2. Legacy unsigned envelope while a secret is configured.
    await a.pub.command('PUBLISH', ch, JSON.stringify({ event: { kind: 'all' }, instanceId: 'attacker' }))
    // 3. v:1 with a wrong signature.
    const badPayload = { event: { kind: 'all' }, instanceId: 'attacker', ts: Date.now() }
    await a.pub.command('PUBLISH', ch, JSON.stringify({ payload: badPayload, sig: 'ab'.repeat(32), v: 1 }))
    // 4. Correctly signed but outside the 30 s replay window.
    const oldPayload = { event: { kind: 'all' }, instanceId: 'attacker', ts: Date.now() - 60_000 }
    await a.pub.command('PUBLISH', ch, JSON.stringify({ payload: oldPayload, sig: sign(oldPayload), v: 1 }))
    // 5. Correctly signed but dated into the future beyond the window.
    const futurePayload = { event: { kind: 'all' }, instanceId: 'attacker', ts: Date.now() + 60_000 }
    await a.pub.command('PUBLISH', ch, JSON.stringify({ payload: futurePayload, sig: sign(futurePayload), v: 1 }))

    await new Promise((r) => setTimeout(r, 400))
    expect(await b.engine.can('f1', 'read', READ_POST), 'a forged or replayed envelope was accepted').toBe(true)

    // Control: a correctly signed, in-window envelope IS accepted, which proves
    // the probe above can detect acceptance.
    const goodPayload = { event: { kind: 'all' }, instanceId: 'another-node', ts: Date.now() }
    await a.pub.command('PUBLISH', ch, JSON.stringify({ payload: goodPayload, sig: sign(goodPayload), v: 1 }))
    const ms = await waitFor(async () => (await b.engine.can('f1', 'read', READ_POST)) === false, 3_000)
    expect(ms, 'the probe cannot detect an accepted envelope - the negative results above are worthless').not.toBeNull()
  }, 60_000)

  it('an in-window signed envelope can be replayed verbatim by anyone who can read the channel', async () => {
    const ch = channel('replay')
    const { a, b } = await armForgeryProbe('f2', ch)

    // An eavesdropper on the channel captures one real envelope...
    const spy = await RedisConn.open(redisPort)
    spare.push(spy)
    const captured: string[] = []
    await spy.subscribeChannel(`${ch}-writer`, (m) => captured.push(m))
    // A role write, so the captured envelope is `{kind:'roles', roleId:'admin'}` -
    // an event that would evict f2 on any node that accepts it.
    await a.engine.admin.saveRole({ id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'post' }] })
    const got = await waitFor(() => captured.length > 0, 5_000)
    expect(got).not.toBeNull()

    // ...and replays it onto B's channel. Within 30 s it verifies.
    const raw = captured[0]
    if (raw === undefined) throw new Error('no envelope captured')
    await a.pub.command('PUBLISH', ch, raw)
    const ms = await waitFor(async () => (await b.engine.can('f2', 'read', READ_POST)) === false, 3_000)
    // This is a cache-wipe replay, not a privilege grant: the event vocabulary
    // has no "allow" verb. Recorded so the blast radius is on the record.
    expect(ms, 'a verbatim replay inside the 30 s window was rejected').not.toBeNull()
  }, 60_000)

  it('UNSIGNED mode: anyone with PUBLISH rights wipes the caches of every node on the channel', async () => {
    const ch = channel('unsigned')
    const a = await makeInstance({ channel: `${ch}-writer`, secret: null })
    const b = await makeInstance({ channel: ch, secret: null })
    await seedAdminRole(a)
    await a.engine.admin.assignRole('f3', 'admin')
    await warm(b, 'f3', true)
    await silentlyRevoke('f3')
    expect(await b.engine.can('f3', 'read', READ_POST)).toBe(true)

    await a.pub.command('PUBLISH', ch, JSON.stringify({ event: { kind: 'all' }, instanceId: 'attacker' }))
    const ms = await waitFor(async () => (await b.engine.can('f3', 'read', READ_POST)) === false, 3_000)
    expect(ms, 'unsigned mode rejected a bare legacy envelope').not.toBeNull()
  }, 60_000)

  it('no forged event can produce an ALLOW the database does not have', async () => {
    const ch = channel('noallow')
    const a = await makeInstance({ channel: `${ch}-writer` })
    const b = await makeInstance({ channel: ch })
    await seedAdminRole(a)
    // No assignment at all: the DB answer is deny.
    expect(await b.engine.can('f4', 'read', READ_POST)).toBe(false)

    for (const kind of ['all', 'policies', 'roles', 'subject'] as const) {
      const payload = {
        event: kind === 'subject' ? { kind, subjectId: 'f4' } : { kind },
        instanceId: 'attacker',
        ts: Date.now(),
      }
      await a.pub.command('PUBLISH', ch, JSON.stringify({ payload, sig: sign(payload), v: 1 }))
    }
    await new Promise((r) => setTimeout(r, 400))
    // The invalidate vocabulary is drop-only; it cannot manufacture a grant.
    expect(await b.engine.can('f4', 'read', READ_POST), 'a forged invalidate produced an allow').toBe(false)
  }, 60_000)
})
