/**
 * GitHub is the one provider whose verified address is not on its userinfo endpoint: `/user` carries the
 * *public* profile email, which the account leaves unset by default and which says nothing about
 * verification. `/user/emails` is what the `user:email` scope is requested for, and reading it is what
 * lets `onFederationConflict: 'link-if-verified'` fire for this provider at all.
 */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { afterOAuthBegin } from '~/test/oauth-browser'
import type { OAuth } from '../../core/oauth.types'
import { github } from '../github'

interface MyProfile extends Identities.ProfileMetadataBase {}

type EmailRow = { email: string; primary: boolean; verified: boolean }

/** A GitHub that answers `/user` and `/user/emails`, and nothing else. `emails` of `null` is a token
 *  without the `user:email` scope, which GitHub refuses with a 403. */
function fakeGithub(user: Record<string, unknown>, emails: EmailRow[] | null): typeof globalThis.fetch {
  return vi.fn(async (url: string) => {
    if (url.startsWith('https://github.com/login/oauth/access_token')) {
      return new Response(JSON.stringify({ access_token: 'at', expires_in: 3600, token_type: 'Bearer' }), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }
    if (url === 'https://api.github.com/user/emails') {
      if (emails === null) return new Response('{"message":"Requires user:email"}', { status: 403 })
      return new Response(JSON.stringify(emails), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }
    if (url === 'https://api.github.com/user') {
      return new Response(JSON.stringify(user), { headers: { 'content-type': 'application/json' }, status: 200 })
    }
    throw new Error(`unexpected url ${url}`)
  }) as unknown as typeof globalThis.fetch
}

/** Captures the profile the provider resolved, which is the thing under test. */
function build(
  user: Record<string, unknown>,
  emails: EmailRow[] | null,
  opts: { onFederationConflict?: OAuth.FederationPolicy } = {},
): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile>; seen: OAuth.Profile[] } {
  const seen: OAuth.Profile[] = []
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    providers: [
      github<MyProfile>({
        clientId: 'cid',
        clientSecret: 'csec',
        fetch: fakeGithub(user, emails),
        profileToIdentityProfile: (p) => {
          seen.push(p)
          // GitHub's own convention for an account with no public address. A blank one is refused by
          // the store, as it is by every dialect.
          return { email: p.email ?? `${p.sub}@users.noreply.github.com`, username: p.email ?? 'gh' }
        },
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret-signing-key',
        ...(opts.onFederationConflict !== undefined && { onFederationConflict: opts.onFederationConflict }),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth, seen }
}

async function signIn(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:authGithub', {}))
  return auth.flows.signIn({ input: { code: 'authcode', cookieHeader, state }, providerId: 'oauth:authGithub' })
}

describe('github provider - profile resolution', () => {
  it('takes the primary verified address from /user/emails, not the public profile email', async () => {
    const { auth, seen } = build({ id: 42, login: 'octocat', email: 'public@noreply.example' }, [
      { email: 'primary@x.com', primary: true, verified: true },
    ])
    await signIn(auth)
    expect(seen[0]?.email).toBe('primary@x.com')
    expect(seen[0]?.emailVerified).toBe(true)
  })

  it('reads the email for an account with no public profile email at all, which is the default', async () => {
    // `/user.email` is null unless the account opts in, so reading only userinfo leaves most sign-ins
    // with no address whatsoever.
    const { auth, seen } = build({ id: 42, login: 'octocat', email: null }, [
      { email: 'hidden@x.com', primary: true, verified: true },
    ])
    await signIn(auth)
    expect(seen[0]?.email).toBe('hidden@x.com')
  })

  it('refuses a primary address that is not verified, and a verified one that is not primary', async () => {
    const { auth, seen } = build({ id: 42, login: 'octocat', email: null }, [
      { email: 'unverified-primary@x.com', primary: true, verified: false },
      { email: 'verified-secondary@x.com', primary: false, verified: true },
    ])
    await signIn(auth)
    expect(seen[0]?.email).toBeUndefined()
    expect(seen[0]?.emailVerified).toBeUndefined()
  })

  it('refuses a userinfo with no numeric id, rather than collapsing every bad one onto one sub', async () => {
    const { auth } = build({ id: null, login: 'octocat', email: null }, [
      { email: 'a@x.com', primary: true, verified: true },
    ])
    await expect(signIn(auth)).rejects.toThrow(/PROVIDER_FAILED/)
  })

  it('stringifies the numeric id rather than coercing a missing one', async () => {
    const { auth, seen } = build({ id: 42, login: 'octocat', email: null }, [
      { email: 'a@x.com', primary: true, verified: true },
    ])
    await signIn(auth)
    expect(seen[0]?.sub).toBe('42')
  })
})

describe('github provider - when /user/emails is unavailable', () => {
  it('falls back to the public profile email without claiming it is verified', async () => {
    // A host that narrowed `scopes` gets a 403 here. Sign-in still completes; it just carries no
    // verification claim, which is the same posture the Microsoft provider takes.
    const { auth, seen } = build({ id: 7, login: 'octocat', email: 'public@x.com' }, null)
    await signIn(auth)
    expect(seen[0]?.email).toBe('public@x.com')
    expect(seen[0]?.emailVerified).toBeUndefined()
  })

  it('still signs in when there is no address to be had from either endpoint', async () => {
    const { auth, seen } = build({ id: 7, login: 'octocat', email: null }, null)
    const res = await signIn(auth)
    expect(res.intents.length).toBeGreaterThan(0)
    expect(seen[0]?.email).toBeUndefined()
  })
})

describe("github provider - onFederationConflict: 'link-if-verified'", () => {
  const TAKEN = 'taken@x.com'

  async function withExistingOwner(user: Record<string, unknown>, emails: EmailRow[] | null) {
    const built = build(user, emails, { onFederationConflict: 'link-if-verified' })
    const existing = await built.adapter.identities.create({
      emailVerified: true,
      profile: { email: TAKEN, username: TAKEN },
      providers: [],
    })
    return { ...built, existingId: existing.id }
  }

  it('links the existing account when GitHub says the address is verified', async () => {
    // Before `/user/emails` was read this could not happen: the provider never set `emailVerified`, so
    // the policy rejected every GitHub sign-in it was asked to arbitrate.
    const { auth, adapter, existingId } = await withExistingOwner({ id: 99, email: null, login: 'octocat' }, [
      { email: TAKEN, primary: true, verified: true },
    ])
    const result = await signIn(auth)
    expect(result.session?.identityId).toBe(existingId)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers.map((p) => p.providerSub)).toEqual(['99'])
  })

  it('refuses to link on the public profile email, which carries no verification claim', async () => {
    // The squatting case: `/user/emails` is unavailable, so the address comes from `/user` and nothing
    // says it was verified. An unverified address must not hand over the account that owns it.
    const { auth, adapter, existingId } = await withExistingOwner({ id: 99, email: TAKEN, login: 'octocat' }, null)
    await expect(signIn(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it('refuses to link when the primary address is present but unverified', async () => {
    const { auth, adapter, existingId } = await withExistingOwner({ id: 99, email: TAKEN, login: 'octocat' }, [
      { email: TAKEN, primary: true, verified: false },
    ])
    await expect(signIn(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })
})
