/**
 * LinkedIn OAuth 2.0 / OIDC provider. Uses the v2 userinfo endpoint
 * (OpenID Connect on LinkedIn) so callers do not need the legacy v1
 * profile + email API calls.
 */

import { AuthErrorObject } from '../../../core/errors'
import type { Provider } from '../../../core/types/provider'
import { OAuthClient } from '../core/client'
import { type OAuthProvider, oauthProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const LINKEDIN_ENDPOINTS: OAuthClient.IEndpoints = {
  authorizationEndpoint: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenEndpoint: 'https://www.linkedin.com/oauth/v2/accessToken',
  userinfoEndpoint: 'https://api.linkedin.com/v2/userinfo',
}

export namespace LinkedInOAuth {
  /** LinkedIn-specific options. */
  export interface IOptions<Profile = unknown> extends OAuthProvider.IOptionsBase<Profile> {
    /** Default `['openid', 'profile', 'email']`. */
    scopes?: string[]
  }
}

/** LinkedIn OIDC provider factory. */
export function linkedin<Profile = unknown>(
  opts: LinkedInOAuth.IOptions<Profile>,
): Provider.IProvider<OAuthProvider.IBeginInput, OAuthProvider.ICompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: LINKEDIN_ENDPOINTS,
    scopes: opts.scopes ?? ['openid', 'profile', 'email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'linkedin',
    client,
    endpoints: LINKEDIN_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // safe-extract LinkedIn claims.
      const sub = getUserinfoString(info, 'sub')
      if (sub === undefined) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: 'linkedin',
          detail: 'LinkedIn userinfo missing sub',
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
      if (email !== undefined) out.email = email
      if (getUserinfoBooleanTrue(info, 'email_verified')) out.emailVerified = true
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const picture = getUserinfoString(info, 'picture')
      if (picture !== undefined) out.avatarUrl = picture
      return out
    },
  })
}
