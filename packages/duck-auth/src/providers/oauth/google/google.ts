import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { OAuthClient } from '../core/client'
import type { OAuth } from '../core/oauth.types'
import { oProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const GOOGLE_ENDPOINTS: OAuth.Endpoints = {
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
  revocationEndpoint: 'https://oauth2.googleapis.com/revoke',
}

/** Google oauth 2.0 / OIDC provider. */
export function google<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: OAuth.GoogleOptions<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GOOGLE_ENDPOINTS,
    scopes: opts.scopes ?? ['openid', 'email', 'profile'],
    fetch: opts.fetch,
  })
  return oProvider<Profile>({
    providerId: 'authGoogle',
    client,
    endpoints: GOOGLE_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    nonceStore: opts.nonceStore,
    allowStateReplay: opts.allowStateReplay,
    stateCookie: opts.stateCookie,
    onSignIn: opts.onSignIn,
    onFederationConflict: opts.onFederationConflict,
    profileToIdentityProfile: opts.profileToIdentityProfile,
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // Checked, not asserted: a non-string `sub` would otherwise reach the provider-sub lookup.
      const sub = getUserinfoString(info, 'sub')
      if (sub === undefined) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: 'authGoogle',
          detail: 'Google userinfo missing sub',
        })
      }
      const out: { sub: string; email?: string; emailVerified?: boolean; name?: string; avatarUrl?: string } = { sub }
      const email = getUserinfoString(info, 'email')
      if (email !== undefined) out.email = email
      // Strictly `true`, so a `"true"` or a `1` does not read as verified.
      if (getUserinfoBooleanTrue(info, 'email_verified')) out.emailVerified = true
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const picture = getUserinfoString(info, 'picture')
      if (picture !== undefined) out.avatarUrl = picture
      return out
    },
  })
}
