/**
 * The seven HTTP adapters each take a `getCaller` that switches on the drift check; grpc took none,
 * so `auth.hijack` and the anomaly detectors were off for gRPC traffic with no way for a host to turn
 * them on. These cover the opt-in and, first, that omitting it still refuses nothing.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Hijack } from '~/core/hijack'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { grpcCaller, withGrpc } from '..'
import type { GrpcAdapter } from '../grpc.types'

type Profile = { username: string; email: string }

const SIGNED_IN = { ip: '10.0.0.1', userAgent: 'grpc-node-js/1.9.0 (the client that signed in)' }

function buildAuth(hijack?: Hijack.Cfg) {
  const adapter = new MemoryAdapter<Profile>()
  return new AuthEngine<Profile>({
    baseUrl: 'https://x',
    ...(hijack && { hijack }),
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

async function signIn(auth: AuthEngine<Profile>, fingerprint: { ip?: string; userAgent?: string } = SIGNED_IN) {
  const identity = await auth.identities.create({
    emailVerified: true,
    profile: { email: `${Math.random().toString(36).slice(2)}@x.com`, username: 'a' },
  })
  const { sid } = await auth.sessions.create({
    aal: 1,
    factors: [],
    identityId: identity.id,
    kind: 'user',
    ...fingerprint,
  })
  return sid
}

/** A unary call carrying the session and whatever user agent the caller claims. The engine is
 *  cookie-transported, and `metadataToHeaders` forwards `cookie` for the grpc-web bridges that send it. */
function call(sid: string, userAgent: string): GrpcAdapter.UnaryCall {
  const bag: Record<string, Array<string | Buffer>> = {
    cookie: [`duck-sid=${sid}`],
    'user-agent': [userAgent],
  }
  return {
    identity: null,
    metadata: { get: (k: string) => bag[k] ?? [], set: () => undefined },
    request: {},
    session: null,
  }
}

const run = (h: GrpcAdapter.UnaryHandler, c: GrpcAdapter.UnaryCall) =>
  new Promise<{ code: number; message: string } | null>((resolve) => {
    h(c, (err) => resolve(err))
  })

describe('grpc request security', () => {
  it('leaves a drifted call untouched when getCaller is omitted', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    let ran = false
    await run(
      withGrpc(auth, (_c, cb) => {
        ran = true
        cb(null, {})
      }),
      call(sid, 'curl/8'),
    )

    expect(ran).toBe(true)
    expect(suspicious).not.toHaveBeenCalled()
  })

  it('reports drift once the host supplies getCaller', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    await run(
      withGrpc(auth, (_c, cb) => cb(null, {}), { getCaller: grpcCaller }),
      call(sid, 'curl/8'),
    )

    expect(suspicious).toHaveBeenCalled()
  })

  it('does not flag the client that signed in', async () => {
    const auth = buildAuth()
    // No address on the row, because that is what a gRPC-only session records: see the case below.
    const sid = await signIn(auth, { userAgent: SIGNED_IN.userAgent })
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    await run(
      withGrpc(auth, (_c, cb) => cb(null, {}), { getCaller: grpcCaller }),
      call(sid, SIGNED_IN.userAgent),
    )

    expect(suspicious).not.toHaveBeenCalled()
  })

  it('reads an address the session recorded elsewhere as drift, since metadata carries none', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth) // signed in over HTTP, so the row has an ip
    const suspicious = vi.fn()
    auth.events.on('suspicious', suspicious)

    await run(
      withGrpc(auth, (_c, cb) => cb(null, {}), { getCaller: grpcCaller }),
      call(sid, SIGNED_IN.userAgent),
    )

    // `stripped` under the default `onMissingSignal: 'soften'`. Inherent to `grpcCaller`, which has no
    // address to offer; a host that resolves the peer passes its own `getCaller` and this goes away.
    expect(suspicious).toHaveBeenCalledWith(expect.objectContaining({ signal: 'ip-change' }))
  })

  it('refuses the call when onHijack throws, before the handler runs', async () => {
    const auth = buildAuth()
    const sid = await signIn(auth)
    let ran = false

    const err = await run(
      withGrpc(
        auth,
        (_c, cb) => {
          ran = true
          cb(null, {})
        },
        {
          getCaller: grpcCaller,
          onHijack: () => {
            throw new Error('refused')
          },
        },
      ),
      call(sid, 'curl/8'),
    )

    expect(ran).toBe(false)
    expect(err?.message).toBe('AUTH_MISCONFIGURED')
  })
})
