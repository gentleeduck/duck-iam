/**
 * GitHub is the one provider whose verified address is not on its userinfo endpoint: `/user` carries the
 * *public* profile email, which the account leaves unset by default and which says nothing about
 * verification. `/user/emails` is what the `user:email` scope is requested for, and reading it is what
 * lets `onFederationConflict: 'link-if-verified'` fire for this provider at all.
 */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { memoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import { afterOAuthBegin } from '~/test/oauth-browser'
import { OAuthClient } from '../../core/client'
import type { OAuth } from '../../core/oauth.types'
import { github } from '../github'

interface MyProfile extends Identities.ProfileMetadataBase {}

type EmailRow = { email: string; primary: boolean; verified: boolean }

const TOKEN = { access_token: 'at', expires_in: 3600, token_type: 'bearer' }

/** A GitHub that answers as the real one does: its token endpoint form-encoded unless asked for JSON, and its
 *  API not at all without a User-Agent, which the Workers runtime's fetch never sends. `emails` of `null` is a
 *  token without the `user:email` scope, which GitHub refuses with a 403. */
function fakeGithub(
  user: Record<string, unknown>,
  emails: EmailRow[] | null,
  token: Record<string, string | number> = TOKEN,
): typeof globalThis.fetch {
  return async (input, init) => {
    const url = input instanceof Request ? input.url : String(input)
    const headers = new Headers(init?.headers)
    if (url === 'https://github.com/login/oauth/access_token') {
      if (headers.get('accept')?.includes('application/json')) return Response.json(token)
      const form = new URLSearchParams(Object.entries(token).map(([k, v]) => [k, String(v)]))
      return new Response(form.toString(), {
        headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      })
    }
    if (!headers.get('user-agent')) {
      return new Response(
        'Request forbidden by administrative rules. Please make sure your request has a User-Agent header',
        {
          status: 403,
        },
      )
    }
    if (url === 'https://api.github.com/user/emails') {
      if (emails === null) return new Response('{"message":"Requires user:email"}', { status: 403 })
      return Response.json(emails)
    }
    if (url === 'https://api.github.com/user') return Response.json(user)
    throw new Error(`unexpected url ${url}`)
  }
}

/** Captures the profile the provider resolved, which is the thing under test. */
function build(
  user: Record<string, unknown>,
  emails: EmailRow[] | null,
  opts: {
    onFederationConflict?: OAuth.FederationPolicy
    refuseProfile?: boolean
    token?: Record<string, string | number>
  } = {},
): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile>; seen: OAuth.Profile[] } {
  const seen: OAuth.Profile[] = []
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    providers: [
      github<MyProfile>({
        clientId: 'cid',
        clientSecret: 'csec',
        fetch: fakeGithub(user, emails, opts.token),
        profileToIdentityProfile: (p) => {
          seen.push(p)
          if (opts.refuseProfile) return null
          // GitHub's own convention for an account with no public address. A blank one is refused by
          // the store, as it is by every dialect.
          return { email: p.email ?? `${p.sub}@users.noreply.github.com`, username: p.email ?? 'gh' }
        },
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret-signing-key',
        nonceStore: memoryDPoPNonceStore(),
        ...(opts.onFederationConflict !== undefined && { onFederationConflict: opts.onFederationConflict }),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  return { adapter, auth, seen }
}

async function signIn(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:github', {}))
  return auth.flows.signIn({ input: { code: 'authcode', cookieHeader, state }, providerId: 'oauth:github' })
}

describe('github provider - its token endpoint and API as GitHub answers them', () => {
  it('signs in, though the token endpoint answers form-encoded unless asked for JSON', async () => {
    const { auth, seen } = build({ id: 42, login: 'octocat', email: null }, [])
    const res = await signIn(auth)
    expect(res.session?.identityId).toBeTruthy()
    expect(seen[0]?.sub).toBe('42')
  })

  it("refuses the error GitHub's token endpoint answers with a 200, and creates nobody", async () => {
    const { auth, adapter } = build({ id: 42, login: 'octocat', email: null }, [], {
      token: { error: 'bad_verification_code', error_description: 'The code passed is incorrect or expired.' },
    })
    await expect(signIn(auth)).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    await expect(
      adapter.identities.find({ providerId: 'oauth:github', providerSub: '42', tenantId: null }),
    ).rejects.toMatchObject({
      code: 'AUTH_IDENTITY_NOT_FOUND',
    })
  })

  it('reads /user and /user/emails through a fetch that sends no User-Agent, as the Workers runtime does', async () => {
    const { auth, seen } = build({ id: 42, login: 'octocat', email: null }, [
      { email: 'primary@x.com', primary: true, verified: true },
    ])
    await signIn(auth)
    expect(seen[0]).toMatchObject({ sub: '42', email: 'primary@x.com', emailVerified: true })
  })

  it("refreshes a GitHub App's token at the same endpoint", async () => {
    const client = new OAuthClient({
      clientId: 'cid',
      clientSecret: 'csec',
      endpoints: {
        authorizationEndpoint: 'https://github.com/login/oauth/authorize',
        tokenEndpoint: 'https://github.com/login/oauth/access_token',
      },
      fetch: fakeGithub({}, null, {
        access_token: 'ghu_new',
        expires_in: 28800,
        refresh_token: 'ghr_new',
        token_type: 'bearer',
      }),
      scopes: [],
    })
    await expect(client.refresh('ghr_old')).resolves.toMatchObject({
      access_token: 'ghu_new',
      refresh_token: 'ghr_new',
    })
  })
})

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

  it('refuses a first sign-in the projection answers null for, and creates nobody', async () => {
    const { auth, adapter } = build({ id: 42, login: 'octocat', email: null }, [], { refuseProfile: true })
    await expect(signIn(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    await expect(
      adapter.identities.find({ providerId: 'oauth:github', providerSub: '42', tenantId: null }),
    ).rejects.toMatchObject({
      code: 'AUTH_IDENTITY_NOT_FOUND',
    })
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
