import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { memoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import { afterOAuthBegin } from '~/test/oauth-browser'
import type { OAuth } from '../../core/oauth.types'
import { microsoft } from '../microsoft'

interface P extends Identities.ProfileMetadataBase {}

/** The profile a sign-in resolves from `userinfo`, answered by a Microsoft that never leaves the process. */
async function profileFrom(userinfo: Record<string, unknown>): Promise<OAuth.Profile | undefined> {
  const seen: OAuth.Profile[] = []
  const adapter = new MemoryAdapter<P>()
  const auth = new AuthEngine<P>({
    baseUrl: 'https://app',
    providers: [
      microsoft<P>({
        clientId: 'cid',
        clientSecret: 'csec',
        fetch: async (input) => {
          const url = String(input)
          if (url === 'https://login.microsoftonline.com/common/oauth2/v2.0/token') {
            return Response.json({ access_token: 'at', expires_in: 3600, token_type: 'Bearer' })
          }
          if (url === 'https://graph.microsoft.com/oidc/userinfo') return Response.json(userinfo)
          throw new Error(`unexpected url ${url}`)
        },
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        profileToIdentityProfile: (p) => {
          seen.push(p)
          return { email: p.email ?? `${p.sub}@x.com`, username: p.sub }
        },
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:microsoft', {}))
  await auth.flows.signIn({ input: { code: 'authcode', cookieHeader, state }, providerId: 'oauth:microsoft' })
  return seen[0]
}

describe('microsoft provider - profile', () => {
  it("carries no avatarUrl, since Entra's picture is a Graph URL only the account's own token can read", async () => {
    // The userinfo answer Microsoft documents, picture included.
    const profile = await profileFrom({
      sub: 'OLu859SGc2Sr9ZsqbkG-QbeLgJlb41KcdiPoLYNpSFA',
      name: 'Mikah Ollenburg',
      family_name: 'Ollenburg',
      given_name: 'Mikah',
      picture: 'https://graph.microsoft.com/v1.0/me/photo/$value',
      email: 'mikoll@contoso.com',
    })
    expect(profile).toEqual({
      sub: 'OLu859SGc2Sr9ZsqbkG-QbeLgJlb41KcdiPoLYNpSFA',
      name: 'Mikah Ollenburg',
      email: 'mikoll@contoso.com',
    })
  })
})
