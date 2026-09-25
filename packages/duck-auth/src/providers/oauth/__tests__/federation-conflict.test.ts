import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { memoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import { afterOAuthBegin } from '~/test/oauth-browser'
import { apple } from '../apple/apple'
import type { OAuth } from '../core/oauth.types'
import { google } from '../google/google'
import { microsoft } from '../microsoft/microsoft'

interface MyProfile extends Identities.ProfileMetadataBase {}

const EMAIL = 'taken@x.com'

/** A Google that answers with one fixed userinfo payload and never leaves the process. */
function fakeGoogle(userinfo: Record<string, unknown>): typeof globalThis.fetch {
  return vi.fn(async (url: string) => {
    if (url.startsWith('https://oauth2.googleapis.com/token')) {
      return new Response(JSON.stringify({ access_token: 'at', expires_in: 3600, token_type: 'Bearer' }), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }
    if (url.startsWith('https://openidconnect.googleapis.com/v1/userinfo')) {
      return new Response(JSON.stringify(userinfo), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }
    throw new Error(`unexpected url ${url}`)
  }) as unknown as typeof globalThis.fetch
}

/**
 * An engine with `google()` registered and one identity already owning
 * {@link EMAIL} through a password sign-up - the federation conflict this
 * policy exists to arbitrate.
 */
async function buildAuth(
  userinfo: Record<string, unknown>,
  onFederationConflict?: OAuth.FederationPolicy,
): Promise<{ auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile>; existingId: string }> {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    providers: [
      google<MyProfile>({
        clientId: 'cid',
        clientSecret: 'csec',
        fetch: fakeGoogle(userinfo),
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        ...(onFederationConflict !== undefined && { onFederationConflict }),
        profileToIdentityProfile: (p) => ({ email: p.email ?? '', username: p.email ?? '' }),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const existing = await adapter.identities.create({
    emailVerified: true,
    profile: { email: EMAIL, username: EMAIL },
    providers: [],
  })
  return { adapter, auth, existingId: existing.id }
}

/** Round-trip a real `state` and its pre-auth cookie through `begin`, the way a browser does. */
async function signInThroughGoogle(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:authGoogle', {}))
  return auth.flows.signIn({ input: { code: 'authcode', state, cookieHeader }, providerId: 'oauth:authGoogle' })
}

const VERIFIED = { email: EMAIL, email_verified: true, sub: 'g-1' }
const UNVERIFIED = { email: EMAIL, email_verified: false, sub: 'g-1' }

/**
 * `onFederationConflict` lived on `OAuth.Options` but not on `OptionsBase`, and
 * `oProvider` is not exported from any entrypoint - so no consumer of the six
 * shipped providers could reach any policy but the `'reject'` default. These
 * drive the policy through `google()`, the way a consumer would.
 */
describe('federation conflict policy, through a shipped provider', () => {
  it('rejects by default, leaving the existing identity unlinked', async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED)
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it("links under 'link-if-verified' when the provider says the email is verified", async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED, 'link-if-verified')
    const result = await signInThroughGoogle(auth)
    expect(result.session?.identityId).toBe(existingId)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers.map((p) => p.providerSub)).toEqual(['g-1'])
  })

  it("still rejects under 'link-if-verified' when the email is unverified", async () => {
    // The squatting case the default exists for: anyone who can get an IdP to
    // emit an unverified address gets the account that owns it.
    const { auth, adapter, existingId } = await buildAuth(UNVERIFIED, 'link-if-verified')
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it('hands a callback the conflict and honours its verdict', async () => {
    const seen: unknown[] = []
    const { auth, adapter, existingId } = await buildAuth(UNVERIFIED, async (ctx) => {
      seen.push(ctx)
      return 'link'
    })
    await signInThroughGoogle(auth)
    expect(seen).toEqual([
      {
        existingIdentityId: existingId,
        profile: expect.objectContaining({ sub: 'g-1' }),
        providerId: 'oauth:authGoogle',
      },
    ])
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers.map((p) => p.providerSub)).toEqual(['g-1'])
  })

  it("honours a callback that answers 'reject'", async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED, async () => 'reject')
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })
})

/** A Microsoft that answers with one fixed userinfo payload and never leaves the process. */
function fakeMicrosoft(userinfo: Record<string, unknown>): typeof globalThis.fetch {
  return vi.fn(async (url: string) => {
    if (url.startsWith('https://login.microsoftonline.com/')) {
      return new Response(JSON.stringify({ access_token: 'at', expires_in: 3600, token_type: 'Bearer' }), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }
    if (url.startsWith('https://graph.microsoft.com/oidc/userinfo')) {
      return new Response(JSON.stringify(userinfo), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }
    throw new Error(`unexpected url ${url}`)
  }) as unknown as typeof globalThis.fetch
}

async function buildMicrosoftAuth(
  userinfo: Record<string, unknown>,
  onFederationConflict?: OAuth.FederationPolicy,
): Promise<{ auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile>; existingId: string }> {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    providers: [
      microsoft<MyProfile>({
        clientId: 'cid',
        clientSecret: 'csec',
        fetch: fakeMicrosoft(userinfo),
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        ...(onFederationConflict !== undefined && { onFederationConflict }),
        profileToIdentityProfile: (p) => ({ email: p.email ?? '', username: p.email ?? '' }),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const existing = await adapter.identities.create({
    emailVerified: true,
    profile: { email: EMAIL, username: EMAIL },
    providers: [],
  })
  return { adapter, auth, existingId: existing.id }
}

async function signInThroughMicrosoft(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:authMicrosoft', {}))
  return auth.flows.signIn({ input: { code: 'authcode', state, cookieHeader }, providerId: 'oauth:authMicrosoft' })
}

/**
 * Entra's `email` is mutable, settable per-tenant and explicitly documented as not verified - Microsoft's
 * own guidance is never to use it as a unique identifier. The default `tenant: 'common'` means any Entra
 * tenant can sign in, an attacker's own included, so an `emailVerified: true` asserted from the presence
 * of the claim hands `'link-if-verified'` a cross-tenant takeover.
 */
describe('Microsoft does not assert an email is verified', () => {
  it("refuses to link under 'link-if-verified' on an Entra email alone", async () => {
    const { auth, adapter, existingId } = await buildMicrosoftAuth(
      { email: EMAIL, sub: 'ms-attacker' },
      'link-if-verified',
    )
    await expect(signInThroughMicrosoft(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it('still signs in a brand-new Microsoft user, who has no conflict to arbitrate', async () => {
    const { auth } = await buildMicrosoftAuth({ email: 'fresh@x.com', sub: 'ms-2' }, 'link-if-verified')
    const result = await signInThroughMicrosoft(auth)
    expect(result.session?.identityId).toBeTruthy()
  })
})

/** Apple has no userinfo endpoint: the profile comes out of the id_token in the token response. */
function appleIdToken(claims: Record<string, unknown>): string {
  const part = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${part({ alg: 'ES256', typ: 'JWT' })}.${part(claims)}.sig`
}

function fakeApple(claims: Record<string, unknown>): typeof globalThis.fetch {
  return vi.fn(async (url: string) => {
    if (url.startsWith('https://appleid.apple.com/auth/token')) {
      return new Response(
        JSON.stringify({ access_token: 'at', expires_in: 3600, id_token: appleIdToken(claims), token_type: 'Bearer' }),
        { headers: { 'content-type': 'application/json' }, status: 200 },
      )
    }
    throw new Error(`unexpected url ${url}`)
  }) as unknown as typeof globalThis.fetch
}

async function buildAppleAuth(
  claims: Record<string, unknown>,
  onFederationConflict?: OAuth.FederationPolicy,
): Promise<{ auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile>; existingId: string }> {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    providers: [
      apple<MyProfile>({
        clientId: 'com.example.app',
        fetch: fakeApple(claims),
        keyId: 'KEYID12345',
        privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        teamId: 'TEAM123456',
        ...(onFederationConflict !== undefined && { onFederationConflict }),
        profileToIdentityProfile: (p) => ({ email: p.email ?? '', username: p.email ?? '' }),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const existing = await adapter.identities.create({
    emailVerified: true,
    profile: { email: EMAIL, username: EMAIL },
    providers: [],
  })
  return { adapter, auth, existingId: existing.id }
}

async function signInThroughApple(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:authApple', {}))
  return auth.flows.signIn({ input: { code: 'authcode', state, cookieHeader }, providerId: 'oauth:authApple' })
}

describe('Apple does not read an absent email_verified as verified', () => {
  it("refuses to link under 'link-if-verified' when the claim is missing entirely", async () => {
    const { auth, adapter, existingId } = await buildAppleAuth({ email: EMAIL, sub: 'a-1' }, 'link-if-verified')
    await expect(signInThroughApple(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it('still links when Apple says so, in either the boolean or the string spelling', async () => {
    for (const verified of [true, 'true']) {
      const { auth, adapter, existingId } = await buildAppleAuth(
        { email: EMAIL, email_verified: verified, sub: 'a-1' },
        'link-if-verified',
      )
      const result = await signInThroughApple(auth)
      expect(result.session?.identityId).toBe(existingId)
      const row = await adapter.identities.find({ id: existingId })
      expect(row?.providers.map((p) => p.providerSub)).toEqual(['a-1'])
    }
  })
})
