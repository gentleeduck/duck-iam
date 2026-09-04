import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import type { OAuth } from '../core/oauth.types'
import { google } from '../google/google'

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

/** Round-trip a real `state` through `begin` so the PKCE verifier matches. */
async function signInThroughGoogle(auth: AuthEngine<MyProfile>) {
  const intents = await auth.flows.beginProvider('oauth:authGoogle', {})
  const state = new URL((intents[0] as { url: string }).url).searchParams.get('state') ?? ''
  return auth.flows.signIn({ input: { code: 'authcode', state }, providerId: 'oauth:authGoogle' })
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
    const row = await adapter.identities.findById(existingId)
    expect(row?.providers).toEqual([])
  })

  it("links under 'link-if-verified' when the provider says the email is verified", async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED, 'link-if-verified')
    const result = await signInThroughGoogle(auth)
    expect(result.session?.identityId).toBe(existingId)
    const row = await adapter.identities.findById(existingId)
    expect(row?.providers.map((p) => p.providerSub)).toEqual(['g-1'])
  })

  it("still rejects under 'link-if-verified' when the email is unverified", async () => {
    // The squatting case the default exists for: anyone who can get an IdP to
    // emit an unverified address gets the account that owns it.
    const { auth, adapter, existingId } = await buildAuth(UNVERIFIED, 'link-if-verified')
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.findById(existingId)
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
    const row = await adapter.identities.findById(existingId)
    expect(row?.providers.map((p) => p.providerSub)).toEqual(['g-1'])
  })

  it("honours a callback that answers 'reject'", async () => {
    const { auth, adapter, existingId } = await buildAuth(VERIFIED, async () => 'reject')
    await expect(signInThroughGoogle(auth)).rejects.toThrow(/PROVIDER_FAILED/)
    const row = await adapter.identities.findById(existingId)
    expect(row?.providers).toEqual([])
  })
})
