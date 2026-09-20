import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'
import type { Identities } from '~/core/identities'
import type { Sessions } from '~/core/sessions/sessions.types'
import { SESSION_FIELDS } from '~/test/type-fidelity'
import { createAuthClient } from '../index'

/**
 * The server sends a session with `Response.json(...)`, which is
 * `JSON.stringify`, so every `Date` on the row leaves as an ISO string. The
 * client declares it hands back `Sessions.Me` and `Identities.Me`, whose
 * `createdAt`, `updatedAt`, `expiresAt`, `rotatedAt`, `absoluteExpiresAt`,
 * `deletedAt`, `providers[].addedAt` and `factors[].completedAt` are all typed
 * `Date`.
 */
const NOW = new Date('2026-09-04T10:00:00.000Z')
const LATER = new Date('2026-09-04T11:00:00.000Z')

/** Exactly what the server puts on the wire: the row, `JSON.stringify`d. */
function wireSession() {
  return {
    identity: {
      createdAt: NOW,
      createdBy: null,
      deletedAt: NOW,
      deletedBy: null,
      emailVerified: true,
      id: 'i1',
      profile: { email: 'a@x.com', username: 'a' },
      providers: [{ addedAt: NOW, providerId: 'password', providerSub: 'sub-1' }],
      updatedAt: NOW,
      updatedBy: null,
      version: 1,
    },
    session: {
      aal: 2,
      absoluteExpiresAt: LATER,
      actingAs: { expiresAt: LATER, realIdentityId: 'admin', reason: 'support', startedAt: NOW },
      createdAt: NOW,
      csrfHash: null,
      expiresAt: LATER,
      factors: [{ completedAt: NOW, method: 'totp' }],
      fingerprint: null,
      fresh: true,
      id: 's1',
      identityId: 'i1',
      ip: null,
      kind: 'user',
      rotatedAt: NOW,
      tenantId: null,
      updatedAt: NOW,
      userAgent: null,
    },
  }
}

function clientReturning(data: unknown) {
  const fetchImpl = vi.fn(async () => ({
    ok: true,
    status: 200,
    // The round trip through JSON is the whole point; do not shortcut it.
    text: async () => JSON.stringify({ code: 'AUTH_SESSION_OK', data, ok: true }),
  })) as unknown as typeof globalThis.fetch
  return createAuthClient<{ email: string; username: string }>({ baseUrl: '/auth', fetch: fetchImpl })
}

async function getSession() {
  const res = await clientReturning(wireSession()).getSession()
  if (!res.ok) throw new Error('expected ok')
  return res.data
}

describe('the client hands back the Dates its types promise', () => {
  it('session deadlines are Dates, not ISO strings', async () => {
    const { session } = await getSession()
    expect(session?.createdAt).toBeInstanceOf(Date)
    expect(session?.rotatedAt).toBeInstanceOf(Date)
    expect(session?.expiresAt).toBeInstanceOf(Date)
    expect(session?.absoluteExpiresAt).toBeInstanceOf(Date)
  })

  it('every top-level Date the row type declares survives the wire', async () => {
    // Derived, not listed: `reviveSession` keys off an allowlist, so a field added to the row type
    // without a matching entry there reaches the caller as a string typed `Date`. That is what
    // happened to `updatedAt`, and a hand-written list of assertions is what missed it.
    const { session } = await getSession()
    const declared = Object.entries(SESSION_FIELDS)
      .filter(([key, kind]) => kind === 'date' && !key.includes('.'))
      .map(([key]) => key)
    expect(declared.length).toBeGreaterThan(0)
    for (const key of declared) {
      expect((session as unknown as Record<string, unknown>)[key], key).toBeInstanceOf(Date)
    }
  })

  it('a deadline compares correctly against a Date', async () => {
    const { session } = await getSession()
    // The silent half. `'2026-09-04T11:00:00.000Z' > NOW` is `false`, so an
    // expiry check written the obvious way reports every session as expired -
    // or, with the operands the other way round, never expired.
    expect((session as Sessions.Me).expiresAt > NOW).toBe(true)
    expect((session as Sessions.Me).expiresAt.getTime()).toBe(LATER.getTime())
  })

  it('nested session dates are Dates', async () => {
    const { session } = await getSession()
    expect(session?.factors[0]?.completedAt).toBeInstanceOf(Date)
    expect(session?.actingAs?.startedAt).toBeInstanceOf(Date)
    expect(session?.actingAs?.expiresAt).toBeInstanceOf(Date)
  })

  it('identity dates are Dates', async () => {
    const { identity } = await getSession()
    expect(identity?.createdAt).toBeInstanceOf(Date)
    expect(identity?.updatedAt).toBeInstanceOf(Date)
    expect(identity?.deletedAt).toBeInstanceOf(Date)
    expect(identity?.providers[0]?.addedAt).toBeInstanceOf(Date)
  })

  it('leaves the profile alone, including strings that look like dates', async () => {
    // A reviver that guesses by shape would rewrite user data. `profile` is
    // app-defined and opaque; nothing in it is a `Date` in the row type.
    const wire = wireSession()
    const profile = { email: 'a@x.com', signedUpOn: '2026-01-01T00:00:00.000Z', username: 'a' }
    const res = await clientReturning({ ...wire, identity: { ...wire.identity, profile } }).getSession()
    if (!res.ok) throw new Error('expected ok')
    expect(res.data.identity?.profile).toEqual(profile)
  })

  it('survives a null session and a malformed date without throwing', async () => {
    const empty = await clientReturning({ identity: null, session: null }).getSession()
    expect(empty.ok && empty.data.session).toBeNull()

    const wire = wireSession()
    const res = await clientReturning({
      ...wire,
      session: { ...wire.session, expiresAt: 'not-a-date' },
    }).getSession()
    if (!res.ok) throw new Error('expected ok')
    // Unparseable stays as it arrived rather than becoming an Invalid Date,
    // which would claim to be a Date and compare false against everything.
    expect(res.data.session?.expiresAt).not.toBeInstanceOf(Date)
  })

  it('an empty 200 resolves to a session result, not to null data', async () => {
    // `call` synthesises `data: parsed` for a non-enveloped reply, and an empty
    // body parses to `null`. That used to be returned as `data` under a type
    // promising a `SessionResult`, so `res.data.session` threw.
    const fetchImpl = vi.fn(async () => ({ ok: true, status: 200, text: async () => '' })) as unknown as typeof fetch
    const res = await createAuthClient({ fetch: fetchImpl }).getSession()
    if (!res.ok) throw new Error('expected ok')
    expect(res.data).toEqual({ identity: null, session: null })
  })

  it('the framework clients inherit it, because they all wrap this one', async () => {
    // react / vue / svelte / solid each call `createAuthClient` and re-expose
    // its state; none of them parses a response of its own. Asserting the seam
    // rather than four near-identical hook tests.
    const src = readFileSync(new URL('../../react/index.ts', import.meta.url), 'utf8')
    expect(src).toContain("from '../vanilla'")
  })

  it('onChange subscribers see the revived rows, not the raw ones', async () => {
    const seen: (Identities.Me<{ email: string; username: string }> | null)[] = []
    const client = clientReturning(wireSession())
    client.onChange((s) => seen.push(s.identity))
    await client.getSession()
    expect(seen.at(-1)?.createdAt).toBeInstanceOf(Date)
  })
})
