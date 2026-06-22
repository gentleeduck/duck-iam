import { AuthErrorObject } from '../../../core/errors'
import type { AuthProvider } from '../../../core/types/provider'
import { AuthOAuthClient } from '../core/client'
import { type AuthOAuthProvider, oauthProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const GOOGLE_ENDPOINTS: AuthOAuthClient.IEndpoints = {
  authorizationEndpoint: 'https://accounts.authGoogle.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
  revocationEndpoint: 'https://oauth2.googleapis.com/revoke',
}

export namespace AuthGoogleOAuth {
  /** Google-specific options. Extends `AuthOAuthProvider.IOptionsBase`. */
  export interface IOptions<Profile = unknown> extends AuthOAuthProvider.IOptionsBase<Profile> {
    /** Default `['openid', 'email', 'profile']`. */
    scopes?: string[]
  }
}

/** Google OAuth 2.0 / OIDC provider. */
export function authGoogle<Profile = unknown>(
  opts: AuthGoogleOAuth.IOptions<Profile>,
): AuthProvider.IProvider<AuthOAuthProvider.IBeginInput, AuthOAuthProvider.ICompleteInput, Profile> {
  const client = new AuthOAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GOOGLE_ENDPOINTS,
    scopes: opts.scopes ?? ['openid', 'email', 'profile'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'authGoogle',
    client,
    endpoints: GOOGLE_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && { profileToIdentityProfile: opts.profileToIdentityProfile }),
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // Safe-extract claims; cast would let non-string `sub` reach findByProviderSub.
      const sub = getUserinfoString(info, 'sub')
      if (sub === undefined) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: 'authGoogle',
          detail: 'Google userinfo missing sub',
        })
      }
      const out: { sub: string; email?: string; emailVerified?: boolean; name?: string; avatarUrl?: string } = { sub }
      const email = getUserinfoString(info, 'email')
      if (email !== undefined) out.email = email
      // email_verified must be strictly === true (defends against
      // truthy-but-non-boolean confusion such as `"true"` or `1`).
      if (getUserinfoBooleanTrue(info, 'email_verified')) out.emailVerified = true
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const picture = getUserinfoString(info, 'picture')
      if (picture !== undefined) out.avatarUrl = picture
      return out
    },
  })
}
