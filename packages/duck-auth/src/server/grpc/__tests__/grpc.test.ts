import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { AuthJwtTransport } from '~/core/transport/jwt.transport'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwordProvider } from '~/providers/password'
import { ScryptHasher } from '~/providers/password/hashers/scrypt.hasher'
import { identityInput } from '~/test/store-inputs'
import { GRPC_STATUS, type GrpcAdapter, httpStatusToGrpc, withGrpc } from '../index'

function makeMetadata(initial: Record<string, string> = {}): GrpcAdapter.Metadata {
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

type MyProfile = {
  username: string
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
    providers: [passwordProvider({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
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

describe('withGrpc interceptor', () => {
  let env: ReturnType<typeof buildAuth>

  beforeEach(() => {
    env = buildAuth()
  })

  it('UNAUTHENTICATED when no token + required:true (default)', async () => {
    const handler = vi.fn()
    const wrapped = withGrpc(env.auth, handler)
    const call: GrpcAdapter.UnaryCall<unknown> = {
      metadata: makeMetadata(),
      request: {},
      session: null,
      identity: null,
    }
    await new Promise<void>((resolve) => {
      wrapped(call, (err) => {
        expect(err?.code).toBe(GRPC_STATUS.UNAUTHENTICATED)
        expect(err?.message).toBe('AUTH_UNAUTHENTICATED')
        resolve()
      })
    })
    expect(handler).not.toHaveBeenCalled()
  })

  it('required:false + no token -> handler invoked with no session attached', async () => {
    const handler = vi.fn((call, cb) => cb(null, { ok: true }))
    const wrapped = withGrpc(env.auth, handler, { required: false })
    const call: GrpcAdapter.UnaryCall<unknown> = {
      metadata: makeMetadata(),
      request: {},
      session: null,
      identity: null,
    }
    await new Promise<void>((resolve) => {
      wrapped(call, () => {
        expect(handler).toHaveBeenCalledOnce()
        expect(call.session).toBeNull()
        resolve()
      })
    })
  })

  it('valid bearer token -> handler called with call.session populated', async () => {
    const ident = await env.adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'a@x.com' }, providers: [] }),
      {},
    )
    const { sid, session } = await env.auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    const intents = env.transport.issue(sid, session, { fresh: true, absolute: false })
    const jwt = (intents.find((i) => i.type === 'json')! as { body: { access_token: string } }).body.access_token

    const handler = vi.fn((call, cb) => cb(null, { ok: true }))
    const wrapped = withGrpc(env.auth, handler)
    const call: GrpcAdapter.UnaryCall<unknown> = {
      metadata: makeMetadata({ authorization: `Bearer ${jwt}` }),
      request: {},
      session: null,
      identity: null,
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
    const wrapped = withGrpc(env.auth, handler, {
      required: false,
      headerName: 'x-api-key',
    })
    const call: GrpcAdapter.UnaryCall<unknown> = {
      metadata: makeMetadata({ 'x-api-key': 'no-real-key' }),
      request: {},
      session: null,
      identity: null,
    }
    await new Promise<void>((resolve) => {
      wrapped(call, () => {
        expect(handler).toHaveBeenCalledOnce()
        resolve()
      })
    })
  })
})
