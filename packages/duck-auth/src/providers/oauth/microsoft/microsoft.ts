/** Microsoft Entra ID, formerly Azure AD. */

import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { OAuthClient } from '../core/client'
import type { OAuth } from '../core/oauth.types'
import { oProvider } from '../core/provider'
import { getUserinfoString } from '../core/userinfo'

function endpointsFor(tenant: string): OAuth.Endpoints {
  return {
    authorizationEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    userinfoEndpoint: 'https://graph.microsoft.com/oidc/userinfo',
  }
}

/** Microsoft Entra ID OAuth provider. */
export function microsoft<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: OAuth.MicrosoftOptions<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  const tenant = opts.tenant ?? 'common'
  const endpoints = endpointsFor(tenant)
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints,
    scopes: opts.scopes ?? ['openid', 'profile', 'email', 'User.Read'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oProvider<Profile>({
    providerId: 'authMicrosoft',
    client,
    endpoints,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.onFederationConflict !== undefined && { onFederationConflict: opts.onFederationConflict }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      const sub = getUserinfoString(info, 'sub')
      if (sub === undefined) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: 'authMicrosoft',
          detail: 'Microsoft userinfo missing sub',
        })
      }
      const out: { sub: string; email?: string; name?: string; avatarUrl?: string } = { sub }
      const email = getUserinfoString(info, 'email')
      // SECURITY: carried, never asserted as verified. Entra's `email` is mutable, set per-tenant and
      // documented by Microsoft as unverified - "never use it for authorization" - and the default
      // `tenant: 'common'` lets any tenant sign in, an attacker's own included.
      if (email !== undefined) out.email = email
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const picture = getUserinfoString(info, 'picture')
      if (picture !== undefined) out.avatarUrl = picture
      return out
    },
  })
}
