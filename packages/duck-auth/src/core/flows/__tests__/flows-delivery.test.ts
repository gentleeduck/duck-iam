/**
 * Every flow that mails a link reads the result of the send it made.
 *
 * `Channel.send` reports a failure rather than throwing, so `await channel.send(...)` reads as a
 * delivery whichever it was: three flows answered `ok: true` for a mail nobody sent, and the only
 * record of it was a `providerMessageId` nobody asked for.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Channel } from '~/channels/channels.types'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

const refusing: Channel.Channel = {
  id: 'refusing',
  kind: 'email',
  send: async () => ({ error: 'connection refused', ok: false, retryable: true }),
}

const throwing: Channel.Channel = {
  id: 'throwing',
  kind: 'email',
  send: async () => {
    throw new Error('transport exploded')
  },
}

describe('a flow that mails a link reads what the channel answered', () => {
  let auth: AuthEngine<MyProfile>
  let identityId: string
  let failures: string[]

  beforeEach(async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
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

  it('email verification says so when the channel refused', async () => {
    await auth.flows.requestEmailVerification({ channels: { email: refusing }, identityId })
    expect(failures).toEqual(['email-verification:channel.send rejected delivery'])
  })

  it('a deletion request says so when the channel refused', async () => {
    await auth.flows.requestAccountDeletion({ channels: { email: refusing }, identityId })
    expect(failures).toEqual(['account-deletion:channel.send rejected delivery'])
  })

  it('the cancellation mail that follows a confirmed deletion says so too', async () => {
    await auth.flows.requestAccountDeletion({ channels: { email: refusing }, identityId })
    const token = new URL(await pendingUrl(auth, identityId)).searchParams.get('token')
    failures = []
    await auth.flows.completeAccountDeletion({ channels: { email: refusing }, token: token! })
    expect(failures).toEqual(['account-deletion-cancel:channel.send rejected delivery'])
  })

  it('a channel that throws is reported with its text rather than escaping the flow', async () => {
    await auth.flows.requestEmailVerification({ channels: { email: throwing }, identityId })
    expect(failures[0]).toContain('transport exploded')
  })
})

/** The verification mail is the only place the token appears, so the test reads it back from one. */
async function pendingUrl<P extends Identities.ProfileMetadataBase>(
  auth: AuthEngine<P>,
  identityId: string,
): Promise<string> {
  let seen = ''
  await auth.flows.requestAccountDeletion({
    channels: {
      email: {
        id: 'capture',
        kind: 'email',
        send: async (input) => {
          seen = (input.vars as { url: string }).url
          return { ok: true }
        },
      },
    },
    identityId,
  })
  return seen
}
