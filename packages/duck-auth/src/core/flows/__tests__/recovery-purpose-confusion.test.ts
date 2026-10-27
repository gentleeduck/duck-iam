/**
 * `kind: 'recovery'` holds seven token families told apart only by `metadata.purpose`, so every redeemer has
 * to check it: a token minted for one flow must not spend at another's. Ported from better-auth's
 * GHSA-965c-763c-88jm, where a value minted as OAuth state was redeemable as a magic link.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { authTestDeliver } from '~/test'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

const PURPOSES = Object.values(RECOVERY_PURPOSES)
const STRONG = 'Str0ng-Passw0rd!'

describe('a recovery token relabelled to another purpose', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string
  let channel: ReturnType<typeof authTestDeliver>

  /** The one live row carrying `purpose`, read before anything relabels it. */
  async function rowIdFor(purpose: string, owner: string = identityId): Promise<string> {
    const rows = await adapter.credentials.listByIdentity(owner, 'recovery', {})
    const hit = rows.filter((r) => r.metadata?.purpose === purpose)
    if (hit.length !== 1) throw new Error(`expected one ${purpose} row, found ${hit.length}`)
    return hit[0]!.id
  }

  function mailedToken(): string {
    const url = String(channel.outbox.at(-1)!.vars.url)
    const token = new URL(url).searchParams.get('token')
    if (token === null) throw new Error('the mailed link carried no token')
    return token
  }

  /** Every purpose but one, which is what a redeemer has to turn down. */
  function foreignTo(own: string): string[] {
    return PURPOSES.filter((p) => p !== own)
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter<MyProfile>()
    channel = authTestDeliver()
    auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      deliver: channel.deliver,
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid' }),
    })
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    identityId = ident.id
  })

  it('cannot verify an email address', async () => {
    await auth.flows.requestEmailVerification({ identityId })
    const token = mailedToken()
    const id = await rowIdFor(RECOVERY_PURPOSES.emailVerification)
    for (const purpose of foreignTo(RECOVERY_PURPOSES.emailVerification)) {
      await adapter.credentials.patchMetadata(id, { purpose }, {})
      await expect(auth.flows.completeEmailVerification({ token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    }
    // The companion allow. Everything else about this row is what the redeemer wants, so the label is the
    // only thing the six refusals above can have been about.
    await adapter.credentials.patchMetadata(id, { purpose: RECOVERY_PURPOSES.emailVerification }, {})
    await expect(auth.flows.completeEmailVerification({ token })).resolves.toMatchObject({ identityId })
  })

  it('cannot set a password', async () => {
    await auth.flows.requestPasswordReset({
      findIdentityByEmail: async () => ({ id: identityId }),
      input: { email: 'a@x.com' },
    })
    const token = mailedToken()
    const id = await rowIdFor(RECOVERY_PURPOSES.passwordReset)
    for (const purpose of foreignTo(RECOVERY_PURPOSES.passwordReset)) {
      await adapter.credentials.patchMetadata(id, { purpose }, {})
      await expect(auth.flows.completePasswordReset({ newPassword: STRONG, token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    }
    await adapter.credentials.patchMetadata(id, { purpose: RECOVERY_PURPOSES.passwordReset }, {})
    await expect(auth.flows.completePasswordReset({ newPassword: STRONG, token })).resolves.toMatchObject({ ok: true })
  })

  it('cannot delete an account', async () => {
    await auth.flows.requestAccountDeletion({ identityId })
    const token = mailedToken()
    const id = await rowIdFor(RECOVERY_PURPOSES.accountDeletion)
    for (const purpose of foreignTo(RECOVERY_PURPOSES.accountDeletion)) {
      await adapter.credentials.patchMetadata(id, { purpose }, {})
      await expect(auth.flows.completeAccountDeletion({ token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    }
    await adapter.credentials.patchMetadata(id, { purpose: RECOVERY_PURPOSES.accountDeletion }, {})
    await expect(auth.flows.completeAccountDeletion({ token })).resolves.toMatchObject({ identityId })
  })

  it('cannot undo a deletion', async () => {
    await auth.flows.requestAccountDeletion({ identityId })
    const { cancellationToken } = await auth.flows.completeAccountDeletion({ token: mailedToken() })
    const id = await rowIdFor(RECOVERY_PURPOSES.accountDeletionCancel)
    for (const purpose of foreignTo(RECOVERY_PURPOSES.accountDeletionCancel)) {
      await adapter.credentials.patchMetadata(id, { purpose }, {})
      await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    }
    await adapter.credentials.patchMetadata(id, { purpose: RECOVERY_PURPOSES.accountDeletionCancel }, {})
    await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).resolves.toMatchObject({ identityId })
  })

  it('cannot finish a signup', async () => {
    const { flow, flowToken } = await auth.flows.beginSignUp({ email: 'b@x.com', required: [] })
    const id = await rowIdFor(RECOVERY_PURPOSES.signupFlow, flow.identityId)
    for (const purpose of foreignTo(RECOVERY_PURPOSES.signupFlow)) {
      await adapter.credentials.patchMetadata(id, { purpose }, {})
      await expect(auth.flows.completeSignUp({ flowToken })).rejects.toMatchObject({
        code: 'AUTH_SIGNUP_TOKEN_INVALID',
      })
    }
    await adapter.credentials.patchMetadata(id, { purpose: RECOVERY_PURPOSES.signupFlow }, {})
    const signedIn = await auth.flows.completeSignUp({ flowToken })
    expect(signedIn.session?.identityId).toBe(flow.identityId)
  })

  it('and a signup token, which anyone who names an address is handed, resets no password', async () => {
    // Not relabelled: the token a squatter holds after `beginSignUp` on a live address, spent where it would
    // hand them the account.
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com', required: [] })
    await expect(auth.flows.completePasswordReset({ newPassword: STRONG, token: flowToken })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })
})
