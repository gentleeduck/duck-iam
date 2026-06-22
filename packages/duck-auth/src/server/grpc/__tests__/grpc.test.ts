import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { AuthJwtTransport } from '../../../core/transport/jwt'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AUTH_GRPC_STATUS, type AuthGrpcAdapter, authHttpStatusToGrpc, authWithGrpc } from '../index'

function makeMetadata(initial: Record<string, string> = {}): AuthGrpcAdapter.IMetadata {
  const store = new Map<string, string[]>()
  for (const [k, v] of Object.entries(initial)) store.set(k.toLowerCase(), [v])
  return {
    get(key) {
      return store.get(key.toLowerCase()) ?? []
    },
    set(key, value) {
      const k = key.toLowerCase()
      const existing = store.get(k) ?? []
      existing.push(typeof value === 'string' ? value : value.toString('utf8'))
      store.set(k, existing)
    },
  }
}

interface MyProfile {
  email: string
}

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const transport = new AuthJwtTransport({
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
    limiter: new AuthMemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter, transport }
}

describe('authHttpStatusToGrpc', () => {
  it('maps the standard auth error statuses to canonical gRPC codes', () => {
    expect(authHttpStatusToGrpc(401)).toBe(AUTH_GRPC_STATUS.UNAUTHENTICATED)
    expect(authHttpStatusToGrpc(403)).toBe(AUTH_GRPC_STATUS.PERMISSION_DENIED)
    expect(authHttpStatusToGrpc(429)).toBe(AUTH_GRPC_STATUS.RESOURCE_EXHAUSTED)
    expect(authHttpStatusToGrpc(503)).toBe(AUTH_GRPC_STATUS.UNAVAILABLE)
    expect(authHttpStatusToGrpc(500)).toBe(AUTH_GRPC_STATUS.INTERNAL)
    expect(authHttpStatusToGrpc(400)).toBe(AUTH_GRPC_STATUS.INVALID_ARGUMENT)
    expect(authHttpStatusToGrpc(200)).toBe(AUTH_GRPC_STATUS.OK)
  })
})

describe('authWithGrpc interceptor', () => {
  let env: ReturnType<typeof buildAuth>

  beforeEach(() => {
    env = buildAuth()
  })

  it('UNAUTHENTICATED when no token + required:true (default)', async () => {
    const handler = vi.fn()
    const wrapped = authWithGrpc(env.auth, handler)
    const call: AuthGrpcAdapter.IUnaryCall<unknown> = {
      metadata: makeMetadata(),
      request: {},
    }
    await new Promise<void>((resolve) => {
      wrapped(call, (err) => {
        expect(err?.code).toBe(AUTH_GRPC_STATUS.UNAUTHENTICATED)
        expect(err?.message).toBe('AUTH/UNAUTHENTICATED')
        resolve()
      })
    })
    expect(handler).not.toHaveBeenCalled()
  })

  it('required:false + no token -> handler invoked with no session attached', async () => {
    const handler = vi.fn((call, cb) => cb(null, { ok: true }))
    const wrapped = authWithGrpc(env.auth, handler, { required: false })
    const call: AuthGrpcAdapter.IUnaryCall<unknown> = {
      metadata: makeMetadata(),
      request: {},
    }
    await new Promise<void>((resolve) => {
      wrapped(call, () => {
        expect(handler).toHaveBeenCalledOnce()
        expect(call.session).toBeUndefined()
        resolve()
      })
    })
  })

  it('valid bearer token -> handler called with call.session populated', async () => {
    const ident = await env.adapter.identities.create({ profile: { email: 'a@x.com' }, providers: [] }, {})
    const { sid, session } = await env.auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: Date.now() }],
    })
    const intents = env.transport.issue(sid, session, { fresh: true, absolute: false })
    const jwt = (intents.find((i) => i.type === 'json')! as { body: { access_token: string } }).body.access_token

    const handler = vi.fn((call, cb) => cb(null, { ok: true }))
    const wrapped = authWithGrpc(env.auth, handler)
    const call: AuthGrpcAdapter.IUnaryCall<unknown> = {
      metadata: makeMetadata({ authorization: `Bearer ${jwt}` }),
      request: {},
    }
    await new Promise<void>((resolve) => {
      wrapped(call, (err) => {
        expect(err).toBeNull()
        expect(call.session?.identityId).toBe(ident.id)
        resolve()
      })
    })
    expect(handler).toHaveBeenCalledOnce()
  })

  it('custom headerName is honored', async () => {
    const handler = vi.fn((call, cb) => cb(null, { ok: true }))
    const wrapped = authWithGrpc(env.auth, handler, {
      required: false,
      headerName: 'x-api-key',
    })
    const call: AuthGrpcAdapter.IUnaryCall<unknown> = {
      metadata: makeMetadata({ 'x-api-key': 'no-real-key' }),
      request: {},
    }
    await new Promise<void>((resolve) => {
      wrapped(call, () => {
        expect(handler).toHaveBeenCalledOnce()
        resolve()
      })
    })
  })
})
