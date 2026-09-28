import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId, withActor } from '~/core/actor'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/provider/provider.types'
import { BearerTransport } from '~/core/transport/bearer.transport'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import { GRPC_STATUS, type GrpcAdapter, httpStatusToGrpc, withGrpc } from '../index'

function makeMetadata(initial: Record<string, string> = {}): GrpcAdapter.Metadata {
  return {
    get: (key) => {
      const value = initial[key]
      return value === undefined ? [] : [value]
    },
  }
}

/** The access token `JwtTransport.issue` answers in its json intent. */
function accessToken(intents: Provider.Intent[]): string {
  const body = intents.find((i) => i.type === 'json')?.body
  const token = typeof body === 'object' && body !== null && 'access_token' in body ? body.access_token : null
  if (typeof token !== 'string') throw new Error('issue answered no access token')
  return token
}

type MyProfile = {
  username: string
  email: string
}

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const transport = new JwtTransport({
    signKey: { kid: 'k1', key: 'secret-test-32-bytes-of-material' },
    verifyKeys: [{ kid: 'k1', key: 'secret-test-32-bytes-of-material' }],
    issuer: 'https://app.test',
  })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.test',
    transport,
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [
      passwords({
        hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }),
      }),
    ],
  })
  return { auth, adapter, transport }
}

describe('httpStatusToGrpc', () => {
  it('maps the standard auth error statuses to canonical gRPC codes', () => {
    expect(httpStatusToGrpc(401)).toBe(GRPC_STATUS.UNAUTHENTICATED)
    expect(httpStatusToGrpc(403)).toBe(GRPC_STATUS.PERMISSION_DENIED)
    expect(httpStatusToGrpc(429)).toBe(GRPC_STATUS.RESOURCE_EXHAUSTED)
    expect(httpStatusToGrpc(503)).toBe(GRPC_STATUS.UNAVAILABLE)
    expect(httpStatusToGrpc(500)).toBe(GRPC_STATUS.INTERNAL)
    expect(httpStatusToGrpc(400)).toBe(GRPC_STATUS.INVALID_ARGUMENT)
    expect(httpStatusToGrpc(200)).toBe(GRPC_STATUS.OK)
  })
})

describe('withGrpc', () => {
  let env: ReturnType<typeof buildAuth>

  beforeEach(() => {
    env = buildAuth()
  })

  it('UNAUTHENTICATED when no token + required:true (default)', async () => {
    const handler = vi.fn()
    const wrapped = withGrpc(env.auth, handler)
    const call: GrpcAdapter.UnaryCall<unknown> = { metadata: makeMetadata(), request: {} }
    await new Promise<void>((resolve) => {
      wrapped(call, (err) => {
        expect(err?.code).toBe(GRPC_STATUS.UNAUTHENTICATED)
        expect(err?.message).toBe('AUTH_UNAUTHENTICATED')
        resolve()
      })
    })
    expect(handler).not.toHaveBeenCalled()
  })

  it('logs the cause of a failure it answers as a server fault, and nothing for a refusal', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    const answer = (handler: GrpcAdapter.UnaryHandler) =>
      new Promise<number | undefined>((resolve) => {
        withGrpc(env.auth, handler, { required: false })({ metadata: makeMetadata(), request: {} }, (err) =>
          resolve(err?.code),
        )
      })
    try {
      const crash = new Error('store down')
      const unavailable = new AuthError('AUTH_ADAPTER_UNAVAILABLE')
      expect(
        await answer(() => {
          throw crash
        }),
      ).toBe(GRPC_STATUS.UNKNOWN)
      expect(
        await answer(() => {
          throw unavailable
        }),
      ).toBe(GRPC_STATUS.UNAVAILABLE)
      expect(
        await answer(() => {
          throw new AuthError('AUTH_UNAUTHENTICATED')
        }),
      ).toBe(GRPC_STATUS.UNAUTHENTICATED)
      expect(logged.mock.calls).toEqual([
        ['[@gentleduck/auth] request failed:', crash],
        ['[@gentleduck/auth] request failed:', unavailable],
      ])
    } finally {
      logged.mockRestore()
    }
  })

  it('required:false + no token -> handler invoked with no session attached', async () => {
    const handler = vi.fn((_call, cb) => cb(null, { ok: true }))
    const wrapped = withGrpc(env.auth, handler, { required: false })
    const call: GrpcAdapter.UnaryCall<unknown> = { metadata: makeMetadata(), request: {} }
    await new Promise<void>((resolve) => {
      wrapped(call, () => {
        expect(handler).toHaveBeenCalledOnce()
        expect(call.session).toBeUndefined()
        resolve()
      })
    })
  })

  it('an unauthenticated call runs as nobody inside a system scope; a signed-in one as its identity', async () => {
    const ident = await env.adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'a@x.com' }, providers: [] }),
    )
    const { sid, session } = await env.auth.sessions.create({ identityId: ident.id, kind: 'user', aal: 1, factors: [] })
    const jwt = accessToken(env.transport.issue(sid, session, { fresh: true, absolute: false }))

    const wrapped = withGrpc(env.auth, (_call, cb) => cb(null, actorId()), { required: false })
    const actorFor = (metadata: GrpcAdapter.Metadata) =>
      withActor('system', () => new Promise((resolve) => wrapped({ metadata, request: {} }, (_e, who) => resolve(who))))

    expect(await actorFor(makeMetadata())).toBeNull()
    expect(await actorFor(makeMetadata({ authorization: `Bearer ${jwt}` }))).toBe(ident.id)
  })

  it('valid bearer token -> handler called with call.session populated', async () => {
    const ident = await env.adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'a@x.com' }, providers: [] }),
    )
    const { sid, session } = await env.auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    const jwt = accessToken(env.transport.issue(sid, session, { fresh: true, absolute: false }))

    const handler = vi.fn((call, cb) => cb(null, { ok: true }))
    const wrapped = withGrpc(env.auth, handler)
    const call: GrpcAdapter.UnaryCall<unknown> = {
      metadata: makeMetadata({ authorization: `Bearer ${jwt}` }),
      request: {},
    }
    await new Promise<void>((resolve) => {
      wrapped(call, (err) => {
        expect(err).toBeNull()
        expect(call.session?.identityId).toBe(ident.id)
        expect(call.identity?.id).toBe(ident.id)
        resolve()
      })
    })
    expect(handler).toHaveBeenCalledOnce()
  })

  it('reads the token from headerName and from no other key', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app.test',
      limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new BearerTransport({ header: 'x-api-key' }),
    })
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'a@x.com' }, providers: [] }),
    )
    const { sid } = await auth.sessions.create({ identityId: ident.id, kind: 'user', aal: 1, factors: [] })
    const answer = (opts: GrpcAdapter.WithGrpcOptions) =>
      new Promise<{ code: number } | null>((resolve) =>
        withGrpc(
          auth,
          (_call, cb) => cb(null, {}),
          opts,
        )({ metadata: makeMetadata({ 'x-api-key': `Bearer ${sid}` }), request: {} }, (err) => resolve(err)),
      )

    expect(await answer({ headerName: 'x-api-key' })).toBeNull()
    // `authorization` by default, so the same metadata carries nothing.
    expect(await answer({})).toMatchObject({ code: GRPC_STATUS.UNAUTHENTICATED })
  })
})
