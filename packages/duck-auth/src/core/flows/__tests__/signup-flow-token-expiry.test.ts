/**
 * A signup flow carries two deadlines: the credential row's absolute cap, and `flow.expiresAt`, the
 * sliding thirty-minute window `beginSignUp` writes and every `advanceSignUp` pushes forward. Only the
 * read path checked the first, and nothing anywhere compared the second against the clock — so the two
 * write paths took a token at any age, and `completeSignUp` minted a full session from one. Nothing
 * sweeps the row either: the credential store contract has no `gc`, so the window had no end.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { credentialInput, identityInput } from '~/test/store-inputs'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

const HALF_HOUR = 30 * 60_000
const DAY = 24 * 60 * 60_000

function build(): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile> } {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.test',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) })],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth }
}

/** Run `fn` as though the clock had moved on by `ms`. */
async function later<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  vi.useFakeTimers()
  try {
    vi.setSystemTime(new Date(Date.now() + ms))
    return await fn()
  } finally {
    vi.useRealTimers()
  }
}

describe('a signup flow token stops working when its window closes', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>

  beforeEach(() => {
    ;({ adapter, auth } = build())
  })

  it('advanceSignUp refuses a token whose thirty-minute window has closed', async () => {
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })

    await expect(
      later(HALF_HOUR + 1000, () => auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' })),
    ).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('completeSignUp refuses one too, rather than minting a session on it', async () => {
    // `required: []`, so the window is the only thing that can refuse this.
    const { flow, flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com', required: [] })

    await expect(later(HALF_HOUR + 1000, () => auth.flows.completeSignUp({ flowToken }))).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
    await expect(adapter.sessions.listByIdentity(flow.identityId, {})).resolves.toEqual([])
  })

  it('getSignUpFlow reads the closed window back as null, the way it already read an elapsed credential', async () => {
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })

    await expect(later(HALF_HOUR + 1000, () => auth.flows.getSignUpFlow(flowToken).orNull())).resolves.toBeNull()
  })

  it('an advance slides the window, so a flow somebody is working through survives past the first deadline', async () => {
    // The guard is on the deadline the flow carries, not on its age: this is the case it must not refuse.
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })

    const advanced = await later(HALF_HOUR - 1000, () =>
      auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' }),
    )
    expect(advanced.completed).toContain('email-verified')
    const again = await later(2 * HALF_HOUR - 2000, () =>
      auth.flows.advanceSignUp({ flowToken, stage: 'terms-accepted' }),
    )
    expect(again.completed).toContain('terms-accepted')
  })

  it('a live flow still completes', async () => {
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com', required: [] })

    const out = await auth.flows.completeSignUp({ flowToken })
    expect(out.sid.length).toBeGreaterThan(0)
  })
})

describe("the credential's own cap still refuses a flow claiming to be live", () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string

  beforeEach(async () => {
    ;({ adapter, auth } = build())
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [] }),
    )
    identityId = ident.id
  })

  /** A row whose metadata says the flow is live long after the row itself expires. `beginSignUp` writes
   *  the cap from `flow.absoluteExpiresAt`, so the two only disagree if somebody edited one of them. */
  async function plantOutlivedRow(): Promise<string> {
    const token = 'outlived-token'
    await adapter.credentials.create(
      credentialInput({
        expiresAt: new Date(Date.now() + 1000),
        identityId,
        kind: 'recovery',
        metadata: {
          flow: {
            absoluteExpiresAt: Date.now() + DAY,
            completed: [],
            createdAt: Date.now(),
            data: { email: 'a@x.com' },
            expiresAt: Date.now() + DAY,
            id: 'flow-1',
            identityId,
            required: [],
          },
          purpose: 'signup-flow',
        },
        secret: sha256(token),
      }),
      {},
    )
    return token
  }

  it('advanceSignUp refuses it', async () => {
    const flowToken = await plantOutlivedRow()

    await expect(
      later(2000, () => auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' })),
    ).rejects.toMatchObject({ code: 'AUTH_SIGNUP_TOKEN_INVALID' })
  })

  it('completeSignUp refuses it, and mints nothing', async () => {
    const flowToken = await plantOutlivedRow()

    await expect(later(2000, () => auth.flows.completeSignUp({ flowToken }))).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
    await expect(adapter.sessions.listByIdentity(identityId, {})).resolves.toEqual([])
  })
})
