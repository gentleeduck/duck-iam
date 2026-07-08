import { beforeEach, describe, expect, it } from 'vitest'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import type { Identity } from '../../types/identity'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { sha256 } from '../../crypto'
import { AuthEngine } from '../../engine'
import { ScryptHasher } from '../../password/scrypt'
import { CookieTransport } from '../../transport/cookie'

interface ProfileShape extends Identity.ProfileMetadataBase {
  email: string
  emailVerified?: boolean
}

function build() {
  const adapter = new MemoryAdapter<ProfileShape>()
  const auth = new AuthEngine<ProfileShape>({
    baseUrl: 'https://app.test',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

async function plantFlowRow(
  adapter: MemoryAdapter<ProfileShape>,
  identityId: string,
  metadata: unknown,
): Promise<string> {
  const token = 'tampered-token'
  await adapter.credentials.upsert(
    credentialInput({
      identityId,
      kind: 'recovery',
      secret: sha256(token),
      metadata: metadata as Record<string, unknown>,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    }),
    {},
  )
  return token
}

describe('flows signup - tampered flow metadata', () => {
  let auth: AuthEngine<ProfileShape>
  let adapter: MemoryAdapter<ProfileShape>
  let identityId: string

  beforeEach(async () => {
    const built = build()
    auth = built.auth
    adapter = built.adapter
    const ident = await adapter.identities.create(identityInput({ profile: { username: 'a@x.com', email: 'a@x.com' }, providers: [] }), {})
    identityId = ident.id
  })

  it('rejects flow with non-array completed field (signup state corruption)', async () => {
    // The most dangerous tampering: `completed` typed as a string is
    // accepted by the cast, and `[...flow.completed, opts.stage]`
    // spreads `'abc'` into individual chars - corrupting the state
    // machine. Parser rejects up front.
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: {
        id: 'flow-1',
        identityId,
        required: ['email-verified'],
        completed: 'email-verified', // <- string, not array
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 24 * 60 * 60_000,
        createdAt: Date.now(),
      },
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects flow with non-array required field', async () => {
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: {
        id: 'flow-1',
        identityId,
        required: 'email-verified', // <- string, not array
        completed: [],
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 24 * 60 * 60_000,
        createdAt: Date.now(),
      },
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects flow with unknown required stage (forward-compat-paranoid)', async () => {
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: {
        id: 'flow-1',
        identityId,
        required: ['email-verified', 'unknown-future-stage'],
        completed: ['email-verified'],
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 24 * 60 * 60_000,
        createdAt: Date.now(),
      },
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('drops unknown completed stages (forward-compat-tolerant on the completed side)', async () => {
    // The completed side is tolerant: unknown stages are silently dropped
    // so a forward-compat consumer can store extra completed markers.
    // But this WILL leave the required stages un-completed.
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: {
        id: 'flow-1',
        identityId,
        required: ['email-verified'],
        completed: ['unknown-stage', 'another-unknown'],
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 24 * 60 * 60_000,
        createdAt: Date.now(),
      },
    })
    // The 'email-verified' required stage is NOT in the parsed completed
    // (unknown values dropped) -> SIGNUP_INCOMPLETE, not invalid token.
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_INCOMPLETE',
    })
  })

  it('rejects flow with non-string identityId', async () => {
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: {
        id: 'flow-1',
        identityId: 42, // <- number, not string
        required: ['email-verified'],
        completed: ['email-verified'],
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 24 * 60 * 60_000,
        createdAt: Date.now(),
      },
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects flow with non-finite absoluteExpiresAt', async () => {
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: {
        id: 'flow-1',
        identityId,
        required: ['email-verified'],
        completed: ['email-verified'],
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: 'never', // <- string
        createdAt: Date.now(),
      },
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects flow with kind !== "signup-flow"', async () => {
    // A row keyed under `recovery` but with the wrong purpose marker
    // (e.g. accidentally typed `signup-flux`) must NOT pass.
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flux', // typo
      flow: {
        id: 'flow-1',
        identityId,
        required: [],
        completed: [],
        data: {},
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 24 * 60 * 60_000,
        createdAt: Date.now(),
      },
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects flow with non-plain-object flow field', async () => {
    const token = await plantFlowRow(adapter, identityId, {
      kind: 'signup-flow',
      flow: 'not-an-object',
    })
    await expect(auth.flows.completeSignUp({ flowToken: token })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('well-formed flow still completes successfully (no regression on happy path)', async () => {
    const { flowToken } = await auth.flows.beginSignUp({
      email: 'happy@x.com',
      required: ['email-verified'],
    })
    await auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' })
    const result = await auth.flows.completeSignUp({ flowToken })
    expect(result.session).toBeDefined()
    expect(result.sid).toBeTruthy()
  })
})
