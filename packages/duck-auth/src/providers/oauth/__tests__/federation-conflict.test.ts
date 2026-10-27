import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
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
  return async (input) => {
    const url = String(input)
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
  }
}

/**
 * An engine with `google()` registered and one identity already owning
 * {@link EMAIL} through a password sign-up - the federation conflict this
 * policy exists to arbitrate.
 */
async function buildAuth(
  userinfo: Record<string, unknown>,
  onFederationConflict?: OAuth.FederationPolicy,
  existingEmailVerified = true,
  onSignIn?: OAuth.OptionsBase<MyProfile>['onSignIn'],
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
        ...(onSignIn !== undefined && { onSignIn }),
        profileToIdentityProfile: (p) => ({ email: p.email ?? '', username: p.email ?? '' }),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const existing = await adapter.identities.create({
    emailVerified: existingEmailVerified,
    profile: { email: EMAIL, username: EMAIL },
    providers: [],
  })
  return { adapter, auth, existingId: existing.id }
}

/** Round-trip a real `state` and its pre-auth cookie through `begin`, the way a browser does. */
async function signInThroughGoogle(auth: AuthEngine<MyProfile>, tenantId?: string) {
  const opts = tenantId === undefined ? {} : { tenantId }
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:google', {}, opts))
  return auth.flows.signIn({ input: { code: 'authcode', state, cookieHeader }, providerId: 'oauth:google', ...opts })
}

const VERIFIED = { email: EMAIL, email_verified: true, sub: 'g-1' }
const UNVERIFIED = { email: EMAIL, email_verified: false, sub: 'g-1' }

/** An `onSignIn` that finds by sub, then links by email, then creates, recording which one answered. */
function resolver(answered: string[]): OAuth.OptionsBase<MyProfile>['onSignIn'] {
  return async ({ createIdentity, findByEmail, findByProviderSub, linkProvider, profile }) => {
    const bySub = await findByProviderSub(profile.sub)
    if (bySub) {
      answered.push('sub')
      return { identityId: bySub.id }
    }
    const byEmail = profile.email === undefined ? null : await findByEmail(profile.email)
    if (byEmail) {
      answered.push('email')
      await linkProvider(byEmail.id, profile.sub)
      return { identityId: byEmail.id }
    }
    answered.push('created')
    return { identityId: (await createIdentity({ email: profile.email ?? '', username: profile.email ?? '' })).id }
  }
}

describe('a provider link opens only the tenant it was made in', () => {
  it('signs in to its own tenant, and meets the conflict policy in another or with no tenant', async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED)
    await adapter.identities.link(existingId, { providerId: 'oauth:google', providerSub: 'g-1', tenantId: 'tenant-a' })
    const conflict = { code: 'AUTH_PROVIDER_FAILED', meta: { detail: expect.stringContaining('federation-conflict') } }

    await expect(signInThroughGoogle(auth, 'tenant-b')).rejects.toMatchObject(conflict)
    await expect(signInThroughGoogle(auth)).rejects.toMatchObject(conflict)
    expect((await signInThroughGoogle(auth, 'tenant-a')).session?.identityId).toBe(existingId)
  })

  it('creates a new account in its own tenant', async () => {
    const { auth, adapter } = await buildAuth({ email: 'new@x.com', email_verified: true, sub: 'g-new' })

    const signedIn = await signInThroughGoogle(auth, 'tenant-a')

    const created = await adapter.identities.find({
      providerId: 'oauth:google',
      providerSub: 'g-new',
      tenantId: 'tenant-a',
    })
    expect(created.id).toBe(signedIn.session?.identityId)
  })

  it('links under the conflict policy in the tenant it signed in to', async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED, 'link-if-verified')

    await signInThroughGoogle(auth, 'tenant-a')

    const row = await adapter.identities.find({ id: existingId })
    expect(row.providers).toEqual([expect.objectContaining({ providerSub: 'g-1', tenantId: 'tenant-a' })])
  })

  it('finds and links through onSignIn in its own tenant', async () => {
    const answered: string[] = []
    const { auth } = await buildAuth(VERIFIED, undefined, true, resolver(answered))

    await signInThroughGoogle(auth, 'tenant-a')
    await signInThroughGoogle(auth, 'tenant-a')
    await signInThroughGoogle(auth)

    expect(answered).toEqual(['email', 'sub', 'email'])
  })

  it('creates through onSignIn in its own tenant', async () => {
    const answered: string[] = []
    const userinfo = { email: 'new@x.com', email_verified: true, sub: 'g-new' }
    const { auth } = await buildAuth(userinfo, undefined, true, resolver(answered))

    await signInThroughGoogle(auth, 'tenant-a')
    await signInThroughGoogle(auth, 'tenant-a')

    expect(answered).toEqual(['created', 'sub'])
  })
})

/**
 * `onFederationConflict` lived on `OAuth.Options` but not on `OptionsBase`, so
 * no consumer of the six shipped providers could reach any policy but the
 * `'reject'` default. These drive the policy through `google()`, the way a
 * consumer would.
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

  it("refuses under 'link-if-verified' a second Google account for an identity that already holds one", async () => {
    // Signed in before, unlinked: the store kept the first account, so the second never showed among the
    // identity's links.
    const { auth, adapter, existingId } = await buildAuth({ ...VERIFIED, sub: 'g-2' }, 'link-if-verified')
    await adapter.identities.link(existingId, { providerId: 'oauth:google', providerSub: 'g-1', tenantId: null })

    await expect(signInThroughGoogle(auth)).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })
    const row = await adapter.identities.find({ id: existingId })
    expect(row.providers.map((p) => p.providerSub)).toEqual(['g-1'])
    expect(await adapter.sessions.listByIdentity(existingId)).toEqual([])
  })

  it("still rejects under 'link-if-verified' when the email is unverified", async () => {
    // The squatting case the default exists for: anyone who can get an IdP to
    // emit an unverified address gets the account that owns it.
    const { auth, adapter, existingId } = await buildAuth(UNVERIFIED, 'link-if-verified')
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it("still rejects under 'link-if-verified' when the existing account never verified the address", async () => {
    // Pre-account takeover: a squatter signs up with the victim's address and never verifies it, then the
    // victim's Google sign-in would land in the squatter's account, password and all.
    const { auth, adapter, existingId } = await buildAuth(VERIFIED, 'link-if-verified', false)
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.find({ id: existingId })
    expect(row?.providers).toEqual([])
  })

  it('hands a callback the conflict and honours its verdict', async () => {
    const seen: unknown[] = []
    const { auth, adapter, existingId } = await buildAuth(
      UNVERIFIED,
      async (ctx) => {
        seen.push(ctx)
        return 'link'
      },
      false,
    )
    await signInThroughGoogle(auth)
    expect(seen).toEqual([
      {
        existingEmailVerified: false,
        existingIdentityId: existingId,
        profile: expect.objectContaining({ sub: 'g-1' }),
        providerId: 'oauth:google',
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
  return async (input) => {
    const url = String(input)
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
  }
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
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const existing = await adapter.identities.create({
    emailVerified: true,
    profile: { email: EMAIL, username: EMAIL },
    providers: [],
  })
  return { adapter, auth, existingId: existing.id }
}

async function signInThroughMicrosoft(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:microsoft', {}))
  return auth.flows.signIn({ input: { code: 'authcode', state, cookieHeader }, providerId: 'oauth:microsoft' })
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
  return async (input) => {
    const url = String(input)
    if (url.startsWith('https://appleid.apple.com/auth/token')) {
      return new Response(
        JSON.stringify({ access_token: 'at', expires_in: 3600, id_token: appleIdToken(claims), token_type: 'Bearer' }),
        { headers: { 'content-type': 'application/json' }, status: 200 },
      )
    }
    throw new Error(`unexpected url ${url}`)
  }
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
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const existing = await adapter.identities.create({
    emailVerified: true,
    profile: { email: EMAIL, username: EMAIL },
    providers: [],
  })
  return { adapter, auth, existingId: existing.id }
}

async function signInThroughApple(auth: AuthEngine<MyProfile>) {
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:apple', {}))
  return auth.flows.signIn({ input: { code: 'authcode', state, cookieHeader }, providerId: 'oauth:apple' })
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
