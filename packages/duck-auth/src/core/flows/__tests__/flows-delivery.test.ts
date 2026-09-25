/** Every flow that mails a link reports a `deliver` that refused, and reports it without its text. */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Deliver } from '~/core/flows/flows.delivery'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

describe('a flow that mails a link reads what deliver answered', () => {
  let auth: AuthEngine<MyProfile>
  let identityId: string
  let failures: string[]
  let urls: string[]
  let refuse: boolean

  beforeEach(async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    urls = []
    refuse = true
    const deliver: Deliver = async (message) => {
      urls.push((message.vars as { url?: string }).url ?? '')
      if (refuse) throw new Error('transport exploded')
    }
    auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      deliver,
      limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
      providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) })],
      stores: {
        credentials: adapter.credentials,
        identities: adapter.identities,
        sessions: adapter.sessions,
      },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    identityId = ident.id
    failures = []
    auth.events.on('signin.failed', (payload) => {
      failures.push(`${payload.providerId}:${payload.reason}`)
    })
  })

  it('email verification says so, and does not quote what deliver threw', async () => {
    await auth.flows.requestEmailVerification({ identityId })
    // The thrown text names the recipient and quotes the body it rendered, token URL and all.
    expect(failures).toEqual(['email-verification:deliver threw'])
  })

  it('a deletion request says so when deliver refused', async () => {
    await auth.flows.requestAccountDeletion({ identityId })
    expect(failures).toEqual(['account-deletion:deliver threw'])
  })

  it('the undo link that follows a confirmed deletion says so too', async () => {
    refuse = false
    await auth.flows.requestAccountDeletion({ identityId })
    const token = new URL(urls[0] ?? '').searchParams.get('token')
    failures = []
    refuse = true
    await auth.flows.completeAccountDeletion({ sendUndoLink: true, token: token! })
    expect(failures).toEqual(['account-deletion-cancel:deliver threw'])
  })
})
