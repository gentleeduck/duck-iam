/** The request fingerprint, end to end through the framework adapters. */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthMemoryDeviceFingerprintStore, deviceFingerprintDetector } from '~/core/anomaly'
import type { Anomaly } from '~/core/anomaly/anomaly.types'
import { AuthEngine } from '~/core/engine'
import type { Hijack } from '~/core/hijack'
import { SESSION_COLUMN_CAPS } from '~/core/sessions'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { elysiaCaller, elysiaWithActor } from '~/server/elysia'
import { type ExpressAdapter, expressActorContext, expressCaller } from '~/server/express'
import { fastifyCaller, fastifyWithActor } from '~/server/fastify'
import { type CallerFingerprint, callerContext, requestSecurity } from '~/server/generic'
import { GRPC_STATUS, type GrpcAdapter, grpcCaller, withGrpc } from '~/server/grpc'
import { honoActorContext, honoCaller } from '~/server/hono'
import { koaActorContext, koaCaller } from '~/server/koa'
import { nestActorContext, nestCaller } from '~/server/nestjs'
import { type NextActorOptions, nextCaller, nextWithActor } from '~/server/next'
import { expressRes, fastifyReply, honoCtx, koaCtx } from '~/test/adapter-fakes'

type Profile = { username: string; email: string }

const SIGNED_IN = { ip: '10.0.0.1', userAgent: 'Mozilla/5.0 (the browser that signed in)' }

function buildAuth(hijack?: Hijack.Cfg) {
  const auth = new AuthEngine<Profile>({
    baseUrl: 'https://x',
    ...(hijack && { hijack }),
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: (() => {
      const adapter = new MemoryAdapter<Profile>()
      return { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions }
    })(),
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return auth
}

/** A session whose row carries {@link SIGNED_IN}, so a later request can drift from it. */
async function signIn(auth: AuthEngine<Profile>): Promise<string> {
  const identity = await auth.identities.create({
    emailVerified: true,
    profile: { email: `${Math.random().toString(36).slice(2)}@x.com`, username: 'a' },
  })
  const { sid } = await auth.sessions.create({
    aal: 1,
    factors: [],
    identityId: identity.id,
    kind: 'user',
    ...SIGNED_IN,
  })
  return sid
}

const cookieHeader = (sid: string) => ({ cookie: `duck-sid=${sid}` })

/** An Express request stub carrying an arbitrary fingerprint. */
function expressReq(sid: string, caller: { ip?: string; userAgent?: string }): ExpressAdapter.Request {
  return {
    headers: { ...cookieHeader(sid), ...(caller.userAgent && { 'user-agent': caller.userAgent }) },
    ...(caller.ip && { ip: caller.ip }),
    method: 'POST',
  }
}

describe('the fingerprint check is off until an adapter is given a getCaller', () => {
  it('runs a drifted request untouched when getCaller is omitted', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    await expressActorContext(auth)(expressReq(sid, { ip: '203.0.113.9', userAgent: 'curl/8' }), expressRes, () => {
      ran = true
    })

    // A different IP *and* a different UA, and the default policy would step-up on the UA.
    expect(ran).toBe(true)
    expect(suspicious).not.toHaveBeenCalled()
  })

  it('records a request that supplied nothing, and still runs it under the default policy', async () => {
    // This once returned before the policy was consulted, on the reading that a caller who sends
    // nothing has nothing to compare. Sending nothing is the caller's own choice, so it is compared:
    // both baselines read as stripped, and `onMissingSignal: 'soften'` drops the reaction to
    // `'rotate'`, which throws nothing. The request still runs; what it no longer does is go unrecorded.
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    await expressActorContext(auth, { getCaller: expressCaller })(expressReq(sid, {}), expressRes, () => {
      ran = true
    })
    expect(ran).toBe(true)
    expect(suspicious.mock.calls.map(([p]) => p.signal)).toEqual(['ip-change', 'user-agent-change'])
  })
})

describe('a supplied getCaller reaches the hijack policy', () => {
  it('applies the configured reaction to a User-Agent change', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)

    let ran = false
    let refusal: unknown
    await expressActorContext(auth, { getCaller: expressCaller })(
      expressReq(sid, { ...SIGNED_IN, userAgent: 'curl/8.7.1' }),
      expressRes,
      (err) => {
        if (err) refusal = err
        else ran = true
      },
    )
    // The default `onUserAgentChange` is 'mfa', which `applyReaction` throws. It reaches express as
    // `next(err)`: a rejected async middleware goes nowhere on Express 4 and the request just hangs.
    expect(refusal).toMatchObject({ code: 'AUTH_STEP_UP_REQUIRED' })
    // Refused before the handler, not after it.
    expect(ran).toBe(false)
  })

  it('ends the session on revoke, so the cookie is dead from the address that signed in too', async () => {
    const auth = buildAuth({ onIpChange: 'revoke' })
    const sid = await signIn(auth)
    const revoked = vi.fn()
    auth.events.on('session.revoked', revoked)

    let refusal: unknown
    await expressActorContext(auth, { getCaller: expressCaller })(
      expressReq(sid, { ...SIGNED_IN, ip: '203.0.113.9' }),
      expressRes,
      (err) => {
        refusal = err
      },
    )
    expect(refusal).toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect(revoked).toHaveBeenCalledOnce()
    await expect(auth.sessions.getBySid(sid).orNull()).resolves.toBeNull()
  })

  it('leaves the session live on mfa, which asks for a step-up rather than ending it', async () => {
    const auth = buildAuth({ onIpChange: 'mfa' })
    const sid = await signIn(auth)
    const revoked = vi.fn()
    auth.events.on('session.revoked', revoked)

    let refusal: unknown
    await expressActorContext(auth, { getCaller: expressCaller })(
      expressReq(sid, { ...SIGNED_IN, ip: '203.0.113.9' }),
      expressRes,
      (err) => {
        refusal = err
      },
    )
    expect(refusal).toMatchObject({ code: 'AUTH_STEP_UP_REQUIRED' })
    expect(revoked).not.toHaveBeenCalled()
    await expect(auth.sessions.getBySid(sid)).resolves.toMatchObject({ ip: SIGNED_IN.ip })
  })

  it('emits suspicious on drift the policy chose to ignore, and still runs the handler', async () => {
    const auth = buildAuth({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    await expressActorContext(auth, { getCaller: expressCaller })(
      expressReq(sid, { ip: '203.0.113.9', userAgent: 'curl/8.7.1' }),
      expressRes,
      () => {
        ran = true
      },
    )

    expect(ran).toBe(true)
    // 'ignore' suppresses the reaction, never the audit trail.
    expect(suspicious.mock.calls.map(([e]) => e.signal).sort()).toEqual(['ip-change', 'user-agent-change'])
  })

  it('hands drift to onHijack instead of the configured reaction', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const seen: Array<{ signal: string; reaction: string }> = []

    let ran = false
    await expressActorContext(auth, {
      getCaller: expressCaller,
      // Deliberately does not throw: the app decided to rotate on its own response.
      onHijack: (drift) => {
        seen.push({ reaction: drift.reaction, signal: drift.signal })
      },
    })(expressReq(sid, { ...SIGNED_IN, userAgent: 'curl/8.7.1' }), expressRes, () => {
      ran = true
    })

    expect(seen).toEqual([{ reaction: 'mfa', signal: 'user-agent-change' }])
    expect(ran).toBe(true)
  })

  it('leaves a matching fingerprint alone', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    await expressActorContext(auth, { getCaller: expressCaller })(expressReq(sid, SIGNED_IN), expressRes, () => {
      ran = true
    })
    expect(ran).toBe(true)
    expect(suspicious).not.toHaveBeenCalled()
  })
})

describe('a device is remembered only once the request is let through', () => {
  it.each([
    ['the browser that signed in, served', SIGNED_IN.userAgent, true],
    ['another browser, refused by the hijack policy', 'Mozilla/5.0 (a stolen cookie)', false],
  ])('%s: known afterwards is %s', async (_, userAgent, known) => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const store = new AuthMemoryDeviceFingerprintStore()
    auth.anomaly.register(deviceFingerprintDetector({ compose: (req) => req.userAgent ?? null, store }))
    let ran = false
    await nextWithActor(
      auth,
      async () => {
        ran = true
        return new Response('ok')
      },
      { getCaller: nextCaller },
    )(new Request('https://x/me', { headers: { ...cookieHeader(sid), 'user-agent': userAgent } }))
    const { identityId } = await auth.sessions.getBySid(sid)
    expect({ known: await store.has(String(identityId), userAgent), ran }).toEqual({ known, ran: known })
  })
})

describe('a supplied getCaller reaches the anomaly detectors', () => {
  it('forwards the fingerprint to resolveSession as a request snapshot', async () => {
    const auth = buildAuth({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    const sid = await signIn(auth)
    const snapshots: Anomaly.RequestSnapshot[] = []
    auth.anomaly.register({
      evaluate: async ({ req }) => {
        snapshots.push(req)
        return []
      },
      id: 'record-the-snapshot',
    })

    const before = Date.now()
    await expressActorContext(auth, { getCaller: expressCaller })(expressReq(sid, SIGNED_IN), expressRes, () => {})

    // Without a snapshot the detectors never run at all, which is the state this fixes.
    expect(snapshots).toHaveLength(1)
    expect(snapshots[0]).toMatchObject(SIGNED_IN)
    expect(snapshots[0]?.now).toBeGreaterThanOrEqual(before)
  })

  /** One request on a session that has not drifted, so only a detector scoring `score` can refuse it. */
  async function verdict(score: number, opts: NextActorOptions = {}): Promise<{ outcome: unknown; ran: boolean }> {
    const auth = buildAuth({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    const sid = await signIn(auth)
    auth.anomaly.register({ evaluate: async () => [{ evidence: {}, kind: 'scored', score }], id: 'scored' })
    let ran = false
    const handler = async () => {
      ran = true
      return new Response('ok')
    }
    const outcome = await nextWithActor(auth, handler, { getCaller: nextCaller, ...opts })(
      new Request('https://x/me', { headers: { ...cookieHeader(sid), 'user-agent': SIGNED_IN.userAgent } }),
    ).then(
      async (res) => (ran ? 'served' : res.json()),
      (err: unknown) => err,
    )
    return { outcome, ran }
  }

  it('refuses a deny with AUTH_ANOMALY_DENIED and its score, before the handler runs', async () => {
    expect(await verdict(0.99)).toEqual({
      outcome: { error: { code: 'AUTH_ANOMALY_DENIED', score: 0.99, status: 403 }, ok: false },
      ran: false,
    })
    expect(await verdict(0.1)).toEqual({ outcome: 'served', ran: true })
  })

  it('serves a step-up by default: the device detector scores one at every first sighting', async () => {
    expect(await verdict(0.8)).toEqual({ outcome: 'served', ran: true })
  })

  it('hands every verdict but allow to onAnomaly, in place of the default refusal', async () => {
    const seen: string[] = []
    const onAnomaly = ({ decision, score }: Anomaly.Result) => {
      seen.push(`${decision}@${score}`)
    }
    expect(await verdict(0.99, { onAnomaly })).toEqual({ outcome: 'served', ran: true })
    expect(await verdict(0.8, { onAnomaly })).toEqual({ outcome: 'served', ran: true })
    expect(await verdict(0.1, { onAnomaly })).toEqual({ outcome: 'served', ran: true })
    expect(seen).toEqual(['deny@0.99', 'step-up@0.8'])
  })

  it('refuses when onAnomaly throws, which is how a host acts on a step-up', async () => {
    const stepUp = new Error('step up first')
    const onAnomaly = () => {
      throw stepUp
    }
    expect(await verdict(0.8, { onAnomaly })).toEqual({ outcome: stepUp, ran: false })
  })

  it('audits the drift on a request the verdict refuses first', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    auth.anomaly.register({ evaluate: async () => [{ evidence: {}, kind: 'scored', score: 0.99 }], id: 'scored' })
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    const answer = await nextWithActor(auth, async () => new Response('ok'), { getCaller: nextCaller })(
      new Request('https://x/me', { headers: { ...cookieHeader(sid), 'user-agent': 'curl/8.7.1' } }),
    )
    expect(await answer.json()).toMatchObject({ error: { code: 'AUTH_ANOMALY_DENIED', status: 403 } })
    expect(suspicious.mock.calls.map(([e]) => e.signal)).toContain('user-agent-change')
  })
})

describe('every adapter can read its own fingerprint', () => {
  /**
   * Each `*Caller` reads what its framework resolved and nothing forwarded. Asserted together
   * because the failure they guard against is one adapter quietly reading a header the others
   * refuse to - the divergence `duck-iam` found across its own five.
   */
  it('reads the framework-resolved pair, never a forwarded header', () => {
    const spoofed = { 'user-agent': 'ua/1', 'x-forwarded-for': '1.2.3.4' }

    const req = { headers: spoofed, identity: null, ip: '10.0.0.1', method: 'GET', session: null, url: '/' }
    const raw = new Request('https://x', { headers: spoofed })
    const read = { ip: '10.0.0.1', userAgent: 'ua/1' }

    expect(expressCaller(req)).toEqual(read)
    expect(fastifyCaller(req)).toEqual(read)
    expect(nestCaller(req)).toEqual(read)
    expect(koaCaller(koaCtx(req))).toEqual(read)
    expect(honoCaller(honoCtx(raw, req.ip))).toEqual(read)
    expect(elysiaCaller({ ip: req.ip, request: raw })).toEqual(read)
    // A Web Request has no resolved peer, and the header that would stand in for one is written
    // by the caller - so Next reports the UA and declines to guess an IP.
    expect(nextCaller(new Request('https://x', { headers: spoofed }))).toEqual({ userAgent: 'ua/1' })
  })

  it('applies the check in koa, hono, nest, next, fastify and elysia too', async () => {
    const drifted = 'curl/8.7.1'
    const stepUp = { code: 'AUTH_STEP_UP_REQUIRED' }

    const koa = buildAuth()
    const koaSid = await signIn(koa)
    await expect(
      koaActorContext(koa, { getCaller: koaCaller })(
        koaCtx({
          headers: { ...cookieHeader(koaSid), 'user-agent': drifted },
          ip: SIGNED_IN.ip,
          method: 'POST',
        }),
        async () => {},
      ),
    ).rejects.toMatchObject(stepUp)

    // Hono and Next answer the refusal themselves, since each makes any throw a 500.
    let reached = false
    const hono = buildAuth()
    const honoSid = await signIn(hono)
    const honoAnswer = await honoActorContext(hono, { getCaller: honoCaller })(
      honoCtx(
        new Request('https://x/me', { headers: { ...cookieHeader(honoSid), 'user-agent': drifted } }),
        SIGNED_IN.ip,
      ),
      async () => {
        reached = true
      },
    )
    expect(honoAnswer?.status).toBe(401)
    expect(await honoAnswer?.json()).toMatchObject({ error: stepUp })

    const nest = buildAuth()
    const nestSid = await signIn(nest)
    let nestRefusal: unknown
    await nestActorContext(nest, { getCaller: nestCaller })(
      {
        headers: { ...cookieHeader(nestSid), 'user-agent': drifted },
        identity: null,
        ip: SIGNED_IN.ip,
        method: 'POST',
      },
      {},
      (err) => {
        nestRefusal = err
      },
    )
    // Nest runs on express, so the refusal travels as `next(err)` here too.
    expect(nestRefusal).toMatchObject(stepUp)

    const next = buildAuth()
    const nextSid = await signIn(next)
    const nextAnswer = await nextWithActor(
      next,
      async () => {
        reached = true
        return new Response('ok')
      },
      { getCaller: nextCaller },
    )(new Request('https://x/me', { headers: { ...cookieHeader(nextSid), 'user-agent': drifted } }))
    expect(nextAnswer.status).toBe(401)
    expect(await nextAnswer.json()).toMatchObject({ error: stepUp })
    expect(reached).toBe(false)

    const fastify = buildAuth()
    const fastifySid = await signIn(fastify)
    await expect(
      fastifyWithActor(fastify, async () => {}, { getCaller: fastifyCaller })(
        {
          headers: { ...cookieHeader(fastifySid), 'user-agent': drifted },
          ip: SIGNED_IN.ip,
          method: 'POST',
        },
        fastifyReply,
      ),
    ).rejects.toMatchObject(stepUp)

    const elysia = buildAuth()
    const elysiaSid = await signIn(elysia)
    await expect(
      elysiaWithActor(elysia, async () => new Response('ok'), { getCaller: elysiaCaller })({
        ip: SIGNED_IN.ip,
        request: new Request('https://x/me', { headers: { ...cookieHeader(elysiaSid), 'user-agent': drifted } }),
      }),
    ).rejects.toMatchObject(stepUp)
  })
})

describe('a fingerprint is normalised to the same lengths the session row stores', () => {
  /**
   * `SessionsImpl.create` truncates `userAgent` to 512 and `ip` to 64, and `hijack.evaluate` cuts the
   * request's values the same way, so a long User-Agent is the same browser on every request whichever
   * `getCaller` read it, rather than a permanent step-up loop.
   */
  it('truncates to the session column caps, so a stamped value compares equal to itself', () => {
    const long = `Mozilla/5.0 ${'x'.repeat(4000)}`
    const stamped = callerContext({ ip: `1.2.3.4${'5'.repeat(200)}`, userAgent: long })

    expect(stamped.userAgent).toHaveLength(SESSION_COLUMN_CAPS.userAgent)
    expect(stamped.ip).toHaveLength(SESSION_COLUMN_CAPS.ip)
    // Idempotent: what the row stores, read back and normalised again, is unchanged.
    expect(callerContext(stamped)).toEqual(stamped)
  })

  it('compares a getCaller reading the raw header by what the row kept', async () => {
    const auth = buildAuth()
    const identity = await auth.identities.create({
      emailVerified: true,
      profile: { email: 'long@x.com', username: 'a' },
    })
    const long = `${SIGNED_IN.userAgent} ${'x'.repeat(600)}`
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [],
      identityId: identity.id,
      kind: 'user',
      userAgent: long,
    })
    const serve = (userAgent: string) =>
      nextWithActor(auth, async () => new Response('ok'), {
        getCaller: (req) => ({ userAgent: req.headers.get('user-agent') ?? undefined }),
      })(new Request('https://x/me', { headers: { ...cookieHeader(sid), 'user-agent': userAgent } }))

    expect((await serve(long)).status).toBe(200)
    // A browser that differs inside the column still drifts, and the default steps it up.
    expect((await serve(`curl/8 ${'x'.repeat(600)}`)).status).toBe(401)
  })

  it('drops an empty value rather than recording one', () => {
    expect(callerContext({ ip: '', userAgent: '' })).toEqual({})
    // A non-string UA (Node's header bag can hand back an array) is not a fingerprint.
    expect(callerContext({ userAgent: ['a', 'b'] })).toEqual({})
  })

  it('lifts the fingerprint into the snapshot, stamped now, without inventing fields', () => {
    const auth = buildAuth()
    const snapshot = (caller: CallerFingerprint) => requestSecurity(auth, { caller }).requestSnapshot
    const now = vi.spyOn(Date, 'now').mockReturnValue(123)
    try {
      expect(snapshot({ userAgent: 'ua/1' })).toEqual({ now: 123, userAgent: 'ua/1' })
      expect(snapshot({})).toEqual({ now: 123 })
      // The only way a position reaches `impossible-travel`.
      expect(snapshot({ geo: { lat: 1, lon: 2 } })).toEqual({ geo: { lat: 1, lon: 2 }, now: 123 })
    } finally {
      now.mockRestore()
    }
  })
})

/** `onMissingSignal: 'strict'` exists because "sending no header is entirely the caller's choice". Two
 *  adapters resolve no IP at all -- a Web `Request` has no peer and a gRPC call's is on the runtime's
 *  object -- so on those two the User-Agent is the entire fingerprint, and dropping it left
 *  `requestSecurity` with nothing to compare and returning before the policy was ever consulted. */
describe('a caller that supplies no fingerprint at all still meets the policy', () => {
  const STRICT: Hijack.Cfg = { onMissingSignal: 'strict', onUserAgentChange: 'revoke' }

  it('refuses a Next request that dropped the only signal Next reads', async () => {
    const auth = buildAuth(STRICT)
    const sid = await signIn(auth)

    const answer = await nextWithActor(auth, async () => new Response('ok'), { getCaller: nextCaller })(
      new Request('https://x/me', { headers: cookieHeader(sid) }),
    )
    expect(answer.status).toBe(401)
    expect(await answer.json()).toMatchObject({ error: { code: 'AUTH_SESSION_REVOKED' } })
  })

  it('refuses a gRPC call that dropped the only signal gRPC reads', async () => {
    const auth = buildAuth(STRICT)
    const sid = await signIn(auth)
    const metadata: GrpcAdapter.Metadata = { get: (n) => (n === 'cookie' ? [`duck-sid=${sid}`] : []) }

    await expect(
      new Promise((resolve, reject) => {
        withGrpc(auth, (_c, cb) => cb(null, {}), { getCaller: grpcCaller })(
          { metadata, request: {} },
          (err: unknown) => (err ? reject(err) : resolve(null)),
        )
      }),
      // The gRPC adapter maps the refusal to a status before the caller ever sees an `AuthError`.
    ).rejects.toMatchObject({ code: GRPC_STATUS.UNAUTHENTICATED })
  })

  it('already refused the same request on an adapter that resolves an IP', async () => {
    // The control, and the asymmetry: express reads a framework-resolved peer, so stripping the
    // User-Agent left `ip` behind and the policy was consulted all along.
    const auth = buildAuth(STRICT)
    const sid = await signIn(auth)

    let refusal: unknown
    await expressActorContext(auth, { getCaller: expressCaller })(
      expressReq(sid, { ip: SIGNED_IN.ip }),
      expressRes,
      (err) => {
        refusal = err
      },
    )
    expect(refusal).toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('softens to an audit record under the default policy rather than refusing', async () => {
    // The default is `onMissingSignal: 'soften'`, so a stripped signal drops to `'rotate'`, which
    // throws nothing. What changes by default is that the drift is now recorded at all.
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    const res = await nextWithActor(auth, async () => new Response('ok'), { getCaller: nextCaller })(
      new Request('https://x/me', { headers: cookieHeader(sid) }),
    )

    expect(res.status).toBe(200)
    expect(suspicious).toHaveBeenCalledWith(expect.objectContaining({ signal: 'user-agent-change' }))
  })

  it('claims nothing about a session that recorded no fingerprint to begin with', async () => {
    const auth = buildAuth(STRICT)
    const identity = await auth.identities.create({
      emailVerified: true,
      profile: { email: 'no-baseline@x.com', username: 'a' },
    })
    const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    const res = await nextWithActor(auth, async () => new Response('ok'), { getCaller: nextCaller })(
      new Request('https://x/me', { headers: cookieHeader(sid) }),
    )

    expect(res.status).toBe(200)
    expect(suspicious).not.toHaveBeenCalled()
  })

  it('stays off entirely when the host supplied no getCaller', async () => {
    const auth = buildAuth(STRICT)
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    const res = await nextWithActor(
      auth,
      async () => new Response('ok'),
    )(new Request('https://x/me', { headers: cookieHeader(sid) }))

    expect(res.status).toBe(200)
    expect(suspicious).not.toHaveBeenCalled()
  })
})

describe('a rotated session answers to the browser the one before it was issued to', () => {
  const THIEF = { ...SIGNED_IN, userAgent: 'curl/8.7.1' }

  function buildRotatingAuth(): AuthEngine<Profile> {
    const adapter = new MemoryAdapter<Profile>()
    return new AuthEngine<Profile>({
      baseUrl: 'https://x',
      hijack: { onUserAgentChange: 'revoke' },
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      providers: [mfaProvider()],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
  }

  /** `'served'`, or what the wrapper refused the request with. */
  async function answer(auth: AuthEngine<Profile>, sid: string, caller: CallerFingerprint): Promise<unknown> {
    let outcome: unknown = 'served'
    await expressActorContext(auth, { getCaller: expressCaller })(expressReq(sid, caller), expressRes, (err) => {
      if (err) outcome = err
    })
    return outcome
  }

  async function stepUp(auth: AuthEngine<Profile>, sid: string, caller: CallerFingerprint = {}): Promise<string> {
    const { identityId } = await auth.sessions.getBySid(sid)
    const { secret } = await auth.mfa.beginTotpEnrollment(identityId ?? '', 'a@x.com')
    const step = Math.floor(Date.now() / 30_000)
    await auth.mfa.confirmTotpEnrollment(identityId ?? '', totpAt(secret, step))
    const code = totpAt(secret, step + 1)
    return (await auth.flows.completeStepUp({ code, currentSid: sid, method: 'totp', ...caller })).sid
  }

  async function impersonate(auth: AuthEngine<Profile>, sid: string): Promise<string> {
    const target = await auth.identities.create({ profile: { email: 'target@x.com', username: 'target' } })
    const authorize = async () => true
    return (await auth.flows.impersonate({ authorize, realSid: sid, reason: 'support', targetIdentityId: target.id }))
      .sid
  }

  const ROTATIONS: Array<[string, (auth: AuthEngine<Profile>, sid: string) => Promise<string>]> = [
    ['a step-up', (auth, sid) => stepUp(auth, sid)],
    ['an impersonation', impersonate],
    [
      'the release of one',
      async (auth, sid) => (await auth.flows.releaseImpersonation(await impersonate(auth, sid))).sid ?? '',
    ],
  ]

  it.each(ROTATIONS)('holds %s to the browser that signed in', async (_, rotate) => {
    const auth = buildRotatingAuth()
    const sid = await rotate(auth, await signIn(auth))

    expect(await answer(auth, sid, SIGNED_IN)).toBe('served')
    expect(await answer(auth, sid, THIEF)).toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'hijack-policy' },
    })
  })

  it('moves the baseline to the browser that proved the factor, once completeStepUp is handed it', async () => {
    const auth = buildRotatingAuth()
    const updated = { ...SIGNED_IN, userAgent: 'Mozilla/5.0 (the same browser, updated)' }
    const sid = await stepUp(auth, await signIn(auth), updated)

    expect(await answer(auth, sid, updated)).toBe('served')
    expect(await answer(auth, sid, SIGNED_IN)).toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
