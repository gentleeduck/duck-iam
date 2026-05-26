/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Provider } from '../../../core/types/provider'
import { OAuthClient, type OAuthEndpoints } from '../core/client'
import { type OAuthBeginInput, type OAuthCompleteInput, type OAuthOptionsBase, oauthProvider } from '../core/provider'

const GOOGLE_ENDPOINTS: OAuthEndpoints = {
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
  revocationEndpoint: 'https://oauth2.googleapis.com/revoke',
}

/**
 * Google-specific OAuth options. Extends the shared `OAuthOptionsBase` so
 * every IdP provider (google / github / apple / discord / ...) shares the
 * same call-site shape; only IdP-specific fields land here.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface GoogleOAuthOptions<Profile = unknown> extends OAuthOptionsBase<Profile> {
  /** Default `['openid', 'email', 'profile']`. */
  scopes?: string[]
}

/** Google OAuth 2.0 / OIDC provider. */
export function google<Profile = unknown>(
  opts: GoogleOAuthOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GOOGLE_ENDPOINTS,
    scopes: opts.scopes ?? ['openid', 'email', 'profile'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'google',
    client,
    endpoints: GOOGLE_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && { profileToIdentityProfile: opts.profileToIdentityProfile }),
    async fetchProfile(tokens, c) {
      const info = (await c.userinfo(tokens.access_token)) as {
        sub: string
        email?: string
        email_verified?: boolean
        name?: string
        picture?: string
      }
      const out: { sub: string; email?: string; emailVerified?: boolean; name?: string; avatarUrl?: string } = {
        sub: info.sub,
      }
      if (info.email !== undefined) out.email = info.email
      if (info.email_verified !== undefined) out.emailVerified = info.email_verified
      if (info.name !== undefined) out.name = info.name
      if (info.picture !== undefined) out.avatarUrl = info.picture
      return out
    },
  })
}
