/** Every flow that mails a link reports a `deliver` that refused, and reports it without its text. */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { AuthEngine } from '~/core/engine'
import { InMemoryEvents } from '~/core/events/events.memory'
import type { Events } from '~/core/events/events.types'
import type { Deliver } from '~/core/flows/flows.delivery'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { magicLink } from '~/providers/magic-link'
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
      urls.push(message.vars.url)
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

describe('a link mailed without awaiting', () => {
  /** A bus whose sink is down for the one report a failed delivery makes. */
  class ReportsDown extends InMemoryEvents {
    override async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
      if (event === 'signin.failed') throw new Error('sink down')
      return super.emit(event, payload)
    }
  }

  function build(
    send: Deliver,
    events?: Events.IBus,
  ): { auth: AuthEngine<MyProfile>; lookup: (email: string) => Promise<{ id: string } | null> } {
    const adapter = new MemoryAdapter<MyProfile>()
    const lookup = (email: string): Promise<{ id: string } | null> => orNull(adapter.identities.find({ email }))
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      deliver: send,
      ...(events && { events }),
      limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
      providers: [
        magicLink<MyProfile>({ deliver: send, findIdentityByEmail: lookup }),
        passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }),
      ],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    return { auth, lookup }
  }

  it('answers a known address as an unknown one when deliver throws before returning a promise', async () => {
    // A template rendered ahead of the send throws synchronously, quoting the signed URL.
    const send: Deliver = (message) => {
      throw new Error(`could not render ${message.vars.url}`)
    }
    const { auth, lookup } = build(send)
    await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    const failures: string[] = []
    auth.events.on('signin.failed', (payload) => {
      failures.push(`${payload.providerId}:${payload.reason}`)
    })
    for (const email of ['a@x.com', 'b@x.com']) {
      await expect(auth.flows.requestPasswordReset({ findIdentityByEmail: lookup, input: { email } })).resolves.toEqual(
        { ok: true },
      )
      await expect(auth.flows.beginProvider('magic-link', { email })).resolves.toEqual([
        { body: { ok: true }, status: 200, type: 'json' },
      ])
    }
    expect(failures).toEqual(['password-reset:deliver threw', 'magic-link:deliver threw'])
  })

  it('logs a report the bus refused, where it used to reject with nothing awaiting it', async () => {
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason)
    }
    process.on('unhandledRejection', onUnhandled)
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { auth, lookup } = build(async () => {
        throw new Error('smtp down')
      }, new ReportsDown())
      await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
      await auth.flows.requestPasswordReset({ findIdentityByEmail: lookup, input: { email: 'a@x.com' } })
      await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      // Node reports an unhandled rejection once the microtask queue drains.
      await new Promise((r) => setImmediate(r))
      expect(unhandled).toEqual([])
      expect(logged.mock.calls.map(([line]) => line)).toEqual([
        '[@gentleduck/auth] could not report a failed password-reset delivery:',
        '[@gentleduck/auth] could not report a failed magic-link delivery:',
      ])
    } finally {
      process.off('unhandledRejection', onUnhandled)
      logged.mockRestore()
    }
  })
})
