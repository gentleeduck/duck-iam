/** E2E: anomaly and hijack verdicts over real HTTP, on sessions kept in real Postgres. */
import { Pool } from 'pg'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { actorId, withRequestActor } from '~/core/actor'
import {
  type Anomaly,
  authImpossibleTravelDetector,
  authMemoryDeviceFingerprintStore,
  deviceFingerprintDetector,
} from '~/core/anomaly'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events'
import type { Hijack } from '~/core/hijack'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { callerContext, type RequestSecurityOptions, requestSecurity } from '~/server/generic'
import { applyPgSchema, databaseUrl, e2ePrefix, serve } from '~/test/e2e-env'

const PG_URL = databaseUrl()
const suite = PG_URL ? describe : describe.skip

type Profile = { username: string; email: string }

const PASSWORD = 'correct-horse-battery'
const BROWSER = 'Mozilla/5.0 (the browser that signed in)'
const THIEF = 'curl/8.4.0'
const NYC = '40.7128,-74.006'
const TOKYO = '35.6762,139.6503'
const SERVED = { body: 'ok', status: 200 }
const DENIED = { body: { code: 'AUTH_ANOMALY_DENIED' }, status: 403 }

suite('E2E anomaly and hijack verdicts over HTTP on real Postgres', () => {
  let pool: Pool
  let stores: DrizzlePgAdapter<Profile>
  /** One for every app below, so a device one of them remembers is known to the next. */
  const devices = authMemoryDeviceFingerprintStore()
  const planted: string[] = []
  const closing: Array<() => Promise<void>> = []

  /** An app over the shared stores: both shipped detectors, a last-seen map the host writes only from a request
   *  it served, and `requestSecurity` in front of the one route. */
  async function start(
    opts: { anomaly?: Partial<Anomaly.Cfg>; hijack?: Hijack.Cfg; onAnomaly?: RequestSecurityOptions['onAnomaly'] } = {},
  ) {
    const auth = new AuthEngine<Profile>({
      ...(opts.anomaly && { anomaly: opts.anomaly }),
      ...(opts.hijack && { hijack: opts.hijack }),
      baseUrl: 'https://app.test',
      limiter: new MemoryLimiter({ max: 1_000, windowMs: 60_000 }),
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }))
    const lastSeen = new Map<string, { lat: number; lon: number; at: number }>()
    auth.anomaly.register(deviceFingerprintDetector({ authSha256: sha256, store: devices }))
    auth.anomaly.register(authImpossibleTravelDetector({ getLastSeen: async (id) => lastSeen.get(id) ?? null }))
    const suspicious: Events.EventMap['suspicious'][] = []
    auth.events.on('suspicious', (event) => {
      suspicious.push(event)
    })

    let served = 0
    const app = await serve(async (req, headers) => {
      // The host's own geolocation, which an edge resolves and no request carries.
      const position = /^(-?[\d.]+),(-?[\d.]+)$/.exec(headers.get('x-geo') ?? '')
      const geo = position ? { lat: Number(position[1]), lon: Number(position[2]) } : undefined
      const caller = {
        ...callerContext({ ip: req.socket.remoteAddress, userAgent: headers.get('user-agent') }),
        ...(geo && { geo }),
      }
      const security = requestSecurity(auth, { caller, ...(opts.onAnomaly && { onAnomaly: opts.onAnomaly }) })
      return withRequestActor(
        auth,
        { headers },
        async () => {
          served += 1
          const id = actorId()
          if (id && geo) lastSeen.set(id, { ...geo, at: Date.now() })
          return 'ok'
        },
        security,
      )
    })
    closing.push(app.close)

    /** Sign a fresh identity in from {@link BROWSER} on loopback, the fingerprint every request below repeats. */
    const signIn = async (name: string) => {
      const address = `${name}-${e2ePrefix()}@anomaly.test`
      const identity = await auth.identities.create({ profile: { email: address, username: address } })
      planted.push(identity.id)
      await auth.passwords.set(identity.id, PASSWORD, stores.credentials)
      const { sid } = await auth.flows.signIn({
        input: { email: address, password: PASSWORD },
        ip: '127.0.0.1',
        providerId: 'password',
        userAgent: BROWSER,
      })
      return { id: identity.id, sid }
    }
    const get = async (sid: string, geo?: string, userAgent = BROWSER) => {
      const res = await fetch(app.origin, {
        headers: { cookie: `duck-sid=${sid}`, 'user-agent': userAgent, ...(geo && { 'x-geo': geo }) },
      })
      return { body: await res.json(), status: res.status }
    }
    /** Whether the session still resolves, read back from Postgres. */
    const live = async (sid: string) =>
      (await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${sid}` }) }).orNull()) !== null
    return { get, live, served: () => served, signIn, suspicious }
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: PG_URL })
    await applyPgSchema(pool)
    stores = new DrizzlePgAdapter<Profile>(pool)
  }, 60_000)

  afterEach(async () => {
    await Promise.all(closing.splice(0).map((close) => close()))
  })

  afterAll(async () => {
    if (planted.length > 0) await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    await pool?.end()
  })

  it('serves a first sighting as the step-up it scores by default, and the device is known from then on', async () => {
    const app = await start()
    const { id, sid } = await app.signIn('first-sight')

    expect(await app.get(sid)).toEqual(SERVED)
    expect(await app.get(sid)).toEqual(SERVED)
    expect(app.served()).toBe(2)
    expect(app.suspicious).toEqual([
      expect.objectContaining({
        identityId: id,
        meta: { decision: 'step-up', signals: [expect.objectContaining({ kind: 'new-device', source: 'new-device' })] },
      }),
    ])
    // It reaches every sink, so it names the fingerprint and never the address or the browser behind it.
    expect(JSON.stringify(app.suspicious)).not.toMatch(/127\.0\.0\.1|Mozilla/)
  })

  it('refuses a new device under a deny reaction, on the retry too, and serves one already known', async () => {
    const lenient = await start()
    const strict = await start({ anomaly: { reactions: { 'new-device': { 'new-device': 'deny' } } } })

    const stranger = await strict.signIn('stranger')
    expect(await strict.get(stranger.sid)).toEqual(DENIED)
    // A refused device is not remembered, so the retry is a first sighting again.
    expect(await strict.get(stranger.sid)).toEqual(DENIED)
    expect(strict.served()).toBe(0)

    const regular = await lenient.signIn('regular')
    expect(await lenient.get(regular.sid)).toEqual(SERVED)
    expect(await strict.get(regular.sid)).toEqual(SERVED)
  })

  it('scores a hop from where the host last saw the identity, and a refused request moves nothing', async () => {
    const app = await start()
    const { sid } = await app.signIn('traveller')

    expect(await app.get(sid, NYC)).toEqual(SERVED)
    expect(await app.get(sid, TOKYO)).toEqual(DENIED)
    // Still measured from New York: the refusal recorded no position.
    expect(await app.get(sid, TOKYO)).toEqual(DENIED)
    expect(await app.get(sid, NYC)).toEqual(SERVED)
    expect(app.served()).toBe(2)
  })

  it('lets onAnomaly refuse a step-up, forgetting the device so the retry is refused too', async () => {
    let fingerprint = ''
    const app = await start({
      onAnomaly: async ({ decision, signals }, session) => {
        if (decision !== 'step-up') return
        for (const { evidence } of signals) {
          if (typeof evidence.fingerprint !== 'string' || !session.identityId) continue
          fingerprint = evidence.fingerprint
          await devices.forget(session.identityId, fingerprint)
        }
        throw new AuthError('AUTH_STEP_UP_REQUIRED', { challenge: { reason: 'new-device' } })
      },
    })
    const { id, sid } = await app.signIn('stepped-up')
    const stepUp = { body: { code: 'AUTH_STEP_UP_REQUIRED' }, status: 401 }

    expect(await app.get(sid)).toEqual(stepUp)
    expect(await app.get(sid)).toEqual(stepUp)
    expect(app.served()).toBe(0)
    // Once the second factor is in, the host remembers the device itself and the next request is served.
    await devices.remember(id, fingerprint)
    expect(await app.get(sid)).toEqual(SERVED)
  })

  it('ends a session whose browser changed under a revoke policy, where the default only asks for a step-up', async () => {
    const stepping = await start()
    const revoking = await start({ hijack: { onUserAgentChange: 'revoke' } })

    const kept = await stepping.signIn('challenged')
    expect(await stepping.get(kept.sid, undefined, THIEF)).toEqual({
      body: { code: 'AUTH_STEP_UP_REQUIRED' },
      status: 401,
    })
    expect(await stepping.live(kept.sid)).toBe(true)

    const ended = await revoking.signIn('revoked')
    expect(await revoking.get(ended.sid, undefined, THIEF)).toEqual({
      body: { code: 'AUTH_SESSION_REVOKED' },
      status: 401,
    })
    expect(await revoking.live(ended.sid)).toBe(false)
    expect(stepping.served() + revoking.served()).toBe(0)
  })
})
