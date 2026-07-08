/** Microsoft Entra ID (formerly Azure AD) oauth 2.0 / OIDC provider. */
import type { Identity } from '~/core'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/types/provider'
import { OauthClient } from '../core/client'
import { type AuthoProvider, oProvider } from '../core/provider'
import { getUserinfoString } from '../core/userinfo'

function endpointsFor(tenant: string): OauthClient.Endpoints {
  return {
    authorizationEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    userinfoEndpoint: 'https://graph.authMicrosoft.com/oidc/userinfo',
  }
}

export namespace AuthMicrosoftoauth {
  /** Microsoft Entra ID-specific options. */
  export interface IOptions<Profile = unknown> extends AuthoProvider.IOptionsBase<Profile> {
    /**
     * Tenant: `common` (any AAD tenant + personal accounts),
     * `organizations` (any AAD tenant), `consumers` (personal only),
     * or a specific tenant GUID. Default `common`.
     */
    tenant?: string
    /** Default `['openid', 'profile', 'email', 'User.Read']`. */
    scopes?: string[]
  }
}

/** Microsoft Entra ID OIDC provider factory. */
export function authMicrosoft<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: AuthMicrosoftoauth.IOptions<Profile>,
): Provider.Me<AuthoProvider.IBeginInput, AuthoProvider.ICompleteInput, Profile> {
  const tenant = opts.tenant ?? 'common'
  const endpoints = endpointsFor(tenant)
  const client = new OauthClient({
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
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // Safe-extract claims; email is org-verified for work/school accounts.
      const sub = getUserinfoString(info, 'sub')
      if (sub === undefined) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: 'authMicrosoft',
          detail: 'Microsoft userinfo missing sub',
        })
      }
      const out: {
        sub: string
        email?: string
        emailVerified?: boolean
        name?: string
        avatarUrl?: string
      } = { sub }
      const email = getUserinfoString(info, 'email')
      if (email !== undefined) {
        out.email = email
        out.emailVerified = true
      }
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const picture = getUserinfoString(info, 'picture')
      if (picture !== undefined) out.avatarUrl = picture
      return out
    },
  })
}
