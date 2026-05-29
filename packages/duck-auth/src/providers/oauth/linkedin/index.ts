/**
 * @packageDocumentation
 * LinkedIn OAuth 2.0 / OIDC provider. Uses the v2 userinfo endpoint
 * (OpenID Connect on LinkedIn) so callers do not need the legacy v1
 * profile + email API calls.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Provider } from '../../../core/types/provider'
import { OAuthClient, type OAuthEndpoints } from '../core/client'
import { type OAuthBeginInput, type OAuthCompleteInput, type OAuthOptionsBase, oauthProvider } from '../core/provider'

const LINKEDIN_ENDPOINTS: OAuthEndpoints = {
  authorizationEndpoint: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenEndpoint: 'https://www.linkedin.com/oauth/v2/accessToken',
  userinfoEndpoint: 'https://api.linkedin.com/v2/userinfo',
}

/**
 * LinkedIn-specific options. Extends the shared `OAuthOptionsBase` so
 * call-site shape matches the rest of the OAuth providers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface LinkedInOAuthOptions<Profile = unknown> extends OAuthOptionsBase<Profile> {
  /** Default `['openid', 'profile', 'email']`. */
  scopes?: string[]
}

/**
 * LinkedIn OIDC provider factory. Maps the LinkedIn `userinfo` payload
 * (sub / name / given_name / family_name / picture / email /
 * email_verified) into the shared OAuthProfile shape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function linkedin<Profile = unknown>(
  opts: LinkedInOAuthOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
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
      const info = (await c.userinfo(tokens.access_token)) as {
        sub: string
        email?: string
        email_verified?: boolean
        name?: string
        picture?: string
      }
      const out: {
        sub: string
        email?: string
        emailVerified?: boolean
        name?: string
        avatarUrl?: string
      } = { sub: info.sub }
      if (info.email !== undefined) out.email = info.email
      if (info.email_verified !== undefined) out.emailVerified = info.email_verified
      if (info.name !== undefined) out.name = info.name
      if (info.picture !== undefined) out.avatarUrl = info.picture
      return out
    },
  })
}

/**
 * Namespace merge for `LinkedInOAuth`. Co-locates the flat option type
 * alongside the factory.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace LinkedInOAuth {
  /** Alias for `LinkedInOAuthOptions`. */
  export type IOptions = LinkedInOAuthOptions
}
