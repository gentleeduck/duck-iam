import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { memoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import { afterOAuthBegin } from '~/test/oauth-browser'
import type { OAuth } from '../../core/oauth.types'
import { google } from '../../google/google'
import { apple } from '../apple'

interface P extends Identities.ProfileMetadataBase {}

const PEM = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  .privateKey.export({ format: 'pem', type: 'pkcs8' })
  .toString()
const SHARED = { redirectUri: 'https://app/cb', stateSigningSecret: 'super-secret', nonceStore: memoryDPoPNonceStore() }

/** Apple's token endpoint, answering an id_token that carries `claims`. */
function fakeApple(claims: Record<string, unknown>): typeof globalThis.fetch {
  const part = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return async (input) => {
    if (!String(input).startsWith('https://appleid.apple.com/auth/token')) throw new Error(`unexpected ${input}`)
    const id_token = `${part({ alg: 'ES256' })}.${part(claims)}.sig`
    return Response.json({ access_token: 'at', expires_in: 3600, id_token, token_type: 'Bearer' })
  }
}

function appleWith(extra: Partial<OAuth.AppleOptions<P>> = {}) {
  return apple<P>({
    clientId: 'com.example.app',
    keyId: 'KEYID12345',
    privateKey: PEM,
    teamId: 'TEAM123456',
    ...SHARED,
    ...extra,
  })
}

function engine(provider: Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, P>) {
  const adapter = new MemoryAdapter<P>()
  return new AuthEngine<P>({
    baseUrl: 'https://app',
    providers: [provider],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

describe('Sign in with Apple, form_post', () => {
  it.each([
    ['apple', () => appleWith(), 'form_post', 'none'],
    ['google', () => google<P>({ clientId: 'g', clientSecret: 's', ...SHARED }), null, 'lax'],
  ])('%s: response_mode is %s and the pre-auth cookie SameSite=%s', async (_, make, mode, sameSite) => {
    const provider = make()
    const intents = await engine(provider).flows.beginProvider(provider.id, {})
    const redirect = intents.find((i) => i.type === 'redirect')
    const url = new URL(redirect && 'url' in redirect ? redirect.url : '')
    expect(url.searchParams.get('response_mode')).toBe(mode)
    expect(intents).toContainEqual(
      expect.objectContaining({ type: 'setCookie', options: expect.objectContaining({ sameSite, secure: true }) }),
    )
  })

  it('refuses an insecure cookie for Apple, whose SameSite=None a browser drops without Secure', () => {
    expect(() => appleWith({ stateCookie: { name: 'duck-oauth', secure: false } })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: 'oauth.stateCookie: apple posts its callback cross-site and needs secure:true' },
      }),
    )
    expect(() =>
      google<P>({ clientId: 'g', clientSecret: 's', ...SHARED, stateCookie: { name: 'duck-oauth', secure: false } }),
    ).not.toThrow()
  })

  it.each([
    [
      'names the profile from the posted user field',
      '{"name":{"firstName":"Ada","lastName":"Lovelace"}}',
      'Ada Lovelace',
    ],
    ['takes a first name alone', '{"name":{"firstName":"Ada"}}', 'Ada'],
    ['signs in without a name when the field is absent', undefined, undefined],
    ['signs in without a name when the field is not JSON', 'not-json', undefined],
    ['signs in without a name when the field carries none', '{"name":null}', undefined],
  ])('%s', async (_, user, name) => {
    const seen: OAuth.Profile[] = []
    const provider = appleWith({
      fetch: fakeApple({ email: 'signed@x.com', sub: 'a-1' }),
      profileToIdentityProfile: (p) => {
        seen.push(p)
        return { email: p.email ?? '', username: p.sub }
      },
    })
    const auth = engine(provider)
    const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider(provider.id, {}))
    const input = { code: 'authcode', cookieHeader, state, ...(user !== undefined && { user }) }
    const result = await auth.flows.signIn({ input, providerId: provider.id })
    expect(result.session?.identityId).toBeTruthy()
    expect(seen.map((p) => p.name)).toEqual([name])
  })

  it('takes the email from the id_token, never from the posted user field', async () => {
    const seen: OAuth.Profile[] = []
    const provider = appleWith({
      fetch: fakeApple({ email: 'signed@x.com', sub: 'a-1' }),
      profileToIdentityProfile: (p) => {
        seen.push(p)
        return { email: p.email ?? '', username: p.sub }
      },
    })
    const auth = engine(provider)
    const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider(provider.id, {}))
    const user = '{"email":"posted@x.com","name":{"firstName":"Ada"}}'
    await auth.flows.signIn({ input: { code: 'authcode', cookieHeader, state, user }, providerId: provider.id })
    expect(seen.map((p) => p.email)).toEqual(['signed@x.com'])
  })
})
