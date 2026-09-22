/** The request fingerprint, end to end through the framework adapters. */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Anomaly } from '~/core/anomaly/anomaly.types'
import { AuthEngine } from '~/core/engine'
import type { Hijack } from '~/core/hijack'
import { SESSION_COLUMN_CAPS } from '~/core/sessions'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { elysiaCaller, elysiaWithActor } from '~/server/elysia'
import { expressActorContext, expressCaller } from '~/server/express'
import { fastifyCaller, fastifyWithActor } from '~/server/fastify'
import { callerContext, callerSnapshot } from '~/server/generic'
import { GRPC_STATUS, grpcCaller, withGrpc } from '~/server/grpc'
import { honoActorContext, honoCaller } from '~/server/hono'
import { koaActorContext, koaCaller } from '~/server/koa'
import { nestActorContext, nestCaller } from '~/server/nestjs'
import { nextCaller, nextWithActor } from '~/server/next'

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
function expressReq(sid: string, caller: { ip?: string; userAgent?: string }) {
  return {
    headers: { ...cookieHeader(sid), ...(caller.userAgent && { 'user-agent': caller.userAgent }) },
    ...(caller.ip && { ip: caller.ip }),
    method: 'POST',
    url: '/me',
  }
}

// biome-ignore lint/suspicious/noExplicitAny: the middleware never touches the response.
const noRes = {} as any

describe('the fingerprint check is off until an adapter is given a getCaller', () => {
  it('runs a drifted request untouched when getCaller is omitted', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
    await expressActorContext(auth)(expressReq(sid, { ip: '203.0.113.9', userAgent: 'curl/8' }) as any, noRes, () => {
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
    await expressActorContext(auth, { getCaller: expressCaller })(
      // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
      expressReq(sid, {}) as any,
      noRes,
      () => {
        ran = true
      },
    )
    expect(ran).toBe(true)
    expect(suspicious.mock.calls.map(([p]) => p.signal)).toEqual(['ip-change', 'user-agent-change'])
  })
})

describe('a supplied getCaller reaches the hijack policy', () => {
  it('applies the configured reaction to a User-Agent change', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)

    let ran = false
    await expect(
      expressActorContext(auth, { getCaller: expressCaller })(
        // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
        expressReq(sid, { ...SIGNED_IN, userAgent: 'curl/8.7.1' }) as any,
        noRes,
        () => {
          ran = true
        },
      ),
      // The default `onUserAgentChange` is 'mfa', which `applyReaction` throws.
    ).rejects.toMatchObject({ code: 'AUTH_STEP_UP_REQUIRED' })
    // Refused before the handler, not after it.
    expect(ran).toBe(false)
  })

  it('emits suspicious on drift the policy chose to ignore, and still runs the handler', async () => {
    const auth = buildAuth({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    await expressActorContext(auth, { getCaller: expressCaller })(
      // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
      expressReq(sid, { ip: '203.0.113.9', userAgent: 'curl/8.7.1' }) as any,
      noRes,
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
    })(
      // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
      expressReq(sid, { ...SIGNED_IN, userAgent: 'curl/8.7.1' }) as any,
      noRes,
      () => {
        ran = true
      },
    )

    expect(seen).toEqual([{ reaction: 'mfa', signal: 'user-agent-change' }])
    expect(ran).toBe(true)
  })

  it('leaves a matching fingerprint alone', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
    await expressActorContext(auth, { getCaller: expressCaller })(expressReq(sid, SIGNED_IN) as any, noRes, () => {
      ran = true
    })
    expect(ran).toBe(true)
    expect(suspicious).not.toHaveBeenCalled()
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
    // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
    await expressActorContext(auth, { getCaller: expressCaller })(expressReq(sid, SIGNED_IN) as any, noRes, () => {})

    // Without a snapshot the detectors never run at all, which is the state this fixes.
    expect(snapshots).toHaveLength(1)
    expect(snapshots[0]).toMatchObject(SIGNED_IN)
    expect(snapshots[0]?.now).toBeGreaterThanOrEqual(before)
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

    // biome-ignore lint/suspicious/noExplicitAny: minimal per-adapter request stubs.
    expect(expressCaller({ headers: spoofed, ip: '10.0.0.1' } as any)).toEqual({ ip: '10.0.0.1', userAgent: 'ua/1' })
    // biome-ignore lint/suspicious/noExplicitAny: minimal per-adapter request stubs.
    expect(fastifyCaller({ headers: spoofed, ip: '10.0.0.1' } as any)).toEqual({ ip: '10.0.0.1', userAgent: 'ua/1' })
    // biome-ignore lint/suspicious/noExplicitAny: minimal per-adapter request stubs.
    expect(nestCaller({ headers: spoofed, ip: '10.0.0.1' } as any)).toEqual({ ip: '10.0.0.1', userAgent: 'ua/1' })
    // biome-ignore lint/suspicious/noExplicitAny: minimal per-adapter request stubs.
    expect(koaCaller({ request: { headers: spoofed, ip: '10.0.0.1' } } as any)).toEqual({
      ip: '10.0.0.1',
      userAgent: 'ua/1',
    })
    expect(
      honoCaller({ ip: '10.0.0.1', req: { header: (n?: string) => (n === 'user-agent' ? 'ua/1' : undefined) } }),
    ).toEqual({ ip: '10.0.0.1', userAgent: 'ua/1' })
    // biome-ignore lint/suspicious/noExplicitAny: minimal per-adapter request stubs.
    expect(elysiaCaller({ ip: '10.0.0.1', request: new Request('https://x', { headers: spoofed }) } as any)).toEqual({
      ip: '10.0.0.1',
      userAgent: 'ua/1',
    })
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
        // biome-ignore lint/suspicious/noExplicitAny: only `request` is read.
        { request: { headers: { ...cookieHeader(koaSid), 'user-agent': drifted }, ip: SIGNED_IN.ip } } as any,
        async () => {},
      ),
    ).rejects.toMatchObject(stepUp)

    const hono = buildAuth()
    const honoSid = await signIn(hono)
    await expect(
      honoActorContext(hono, { getCaller: honoCaller })(
        {
          ip: SIGNED_IN.ip,
          req: {
            header: (n?: string) => (n === 'user-agent' ? drifted : undefined),
            raw: new Request('https://x/me', { headers: cookieHeader(honoSid) }),
          },
          // biome-ignore lint/suspicious/noExplicitAny: a HonoAdapter.Context stub.
        } as any,
        async () => {},
      ),
    ).rejects.toMatchObject(stepUp)

    const nest = buildAuth()
    const nestSid = await signIn(nest)
    await expect(
      nestActorContext(nest, { getCaller: nestCaller }).use(
        // biome-ignore lint/suspicious/noExplicitAny: a NestAdapter.Request stub.
        {
          headers: { ...cookieHeader(nestSid), 'user-agent': drifted },
          identity: null,
          ip: SIGNED_IN.ip,
          method: 'POST',
          session: null,
          // biome-ignore lint/suspicious/noExplicitAny: a NestAdapter.Request stub.
        } as any,
        {},
        () => {},
      ),
    ).rejects.toMatchObject(stepUp)

    const next = buildAuth()
    const nextSid = await signIn(next)
    await expect(
      nextWithActor(next, async () => new Response('ok'), { getCaller: nextCaller })(
        new Request('https://x/me', { headers: { ...cookieHeader(nextSid), 'user-agent': drifted } }),
      ),
    ).rejects.toMatchObject(stepUp)

    const fastify = buildAuth()
    const fastifySid = await signIn(fastify)
    await expect(
      fastifyWithActor(fastify, async () => {}, { getCaller: fastifyCaller })(
        // biome-ignore lint/suspicious/noExplicitAny: only `headers` and `ip` are read.
        { headers: { ...cookieHeader(fastifySid), 'user-agent': drifted }, ip: SIGNED_IN.ip, method: 'POST' } as any,
        // biome-ignore lint/suspicious/noExplicitAny: the wrapper never touches the reply.
        {} as any,
      ),
    ).rejects.toMatchObject(stepUp)

    const elysia = buildAuth()
    const elysiaSid = await signIn(elysia)
    await expect(
      elysiaWithActor(elysia, async () => new Response('ok'), { getCaller: elysiaCaller })({
        ip: SIGNED_IN.ip,
        request: new Request('https://x/me', { headers: { ...cookieHeader(elysiaSid), 'user-agent': drifted } }),
        // biome-ignore lint/suspicious/noExplicitAny: an ElysiaAdapter.Context stub.
      } as any),
    ).rejects.toMatchObject(stepUp)
  })

  /**
   * The Nest guard leaves its resolved session on the request so the pair costs one
   * `resolveSession` rather than two. That shortcut must not also skip the fingerprint check.
   */
  it('still checks the fingerprint on the session nest reused from its guard', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const resolved = await auth.resolveSession({ headers: new Headers(cookieHeader(sid)) })

    await expect(
      nestActorContext(auth, { getCaller: nestCaller }).use(
        {
          headers: { 'user-agent': 'curl/8.7.1' },
          identity: null,
          ip: SIGNED_IN.ip,
          method: 'POST',
          session: resolved.session,
          // biome-ignore lint/suspicious/noExplicitAny: a NestAdapter.Request stub.
        } as any,
        {},
        () => {},
      ),
    ).rejects.toMatchObject({ code: 'AUTH_STEP_UP_REQUIRED' })
  })
})

describe('a fingerprint is normalised to the same lengths the session row stores', () => {
  /**
   * `SessionsImpl.create` truncates `userAgent` to 512 and `ip` to 64. If `callerContext`
   * normalised to anything else, the value compared on a later request would never equal the
   * value on the row, and a client with a long User-Agent would read as drift on every single
   * request it ever sent - a permanent step-up loop.
   */
  it('truncates to the session column caps, so a stamped value compares equal to itself', () => {
    const long = `Mozilla/5.0 ${'x'.repeat(4000)}`
    const stamped = callerContext({ ip: `1.2.3.4${'5'.repeat(200)}`, userAgent: long })

    expect(stamped.userAgent).toHaveLength(SESSION_COLUMN_CAPS.userAgent)
    expect(stamped.ip).toHaveLength(SESSION_COLUMN_CAPS.ip)
    // Idempotent: what the row stores, read back and normalised again, is unchanged.
    expect(callerContext(stamped)).toEqual(stamped)
  })

  it('drops an empty value rather than recording one', () => {
    expect(callerContext({ ip: '', userAgent: '' })).toEqual({})
    // A non-string UA (Node's header bag can hand back an array) is not a fingerprint.
    expect(callerContext({ userAgent: ['a', 'b'] })).toEqual({})
  })

  it('lifts a fingerprint into a snapshot without inventing fields', () => {
    expect(callerSnapshot({ userAgent: 'ua/1' }, 123)).toEqual({ now: 123, userAgent: 'ua/1' })
    expect(callerSnapshot({}, 123)).toEqual({ now: 123 })
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

    await expect(
      nextWithActor(auth, async () => new Response('ok'), { getCaller: nextCaller })(
        new Request('https://x/me', { headers: cookieHeader(sid) }),
      ),
    ).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('refuses a gRPC call that dropped the only signal gRPC reads', async () => {
    const auth = buildAuth(STRICT)
    const sid = await signIn(auth)
    const metadata = { get: (n: string) => (n === 'cookie' ? [`duck-sid=${sid}`] : []) }

    await expect(
      new Promise((resolve, reject) => {
        // biome-ignore lint/suspicious/noExplicitAny: a GrpcAdapter.UnaryCall stub.
        withGrpc(auth, (_c, cb) => cb(null, {}), { getCaller: grpcCaller })({ metadata } as any, (err: unknown) =>
          err ? reject(err) : resolve(null),
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

    await expect(
      // biome-ignore lint/suspicious/noExplicitAny: an ExpressAdapter.Request stub.
      expressActorContext(auth, { getCaller: expressCaller })(
        expressReq(sid, { ip: SIGNED_IN.ip }) as any,
        noRes,
        () => {},
      ),
    ).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
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
