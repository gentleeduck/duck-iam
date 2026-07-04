import { AuthError } from '../../../core/errors'
import type { AuthProvider } from '../../../core/types/provider'
import { AuthoauthClient } from '../core/client'
import { type AuthoauthProvider, oauthProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const GOOGLE_ENDPOINTS: AuthoauthClient.IEndpoints = {
  authorizationEndpoint: 'https://accounts.authGoogle.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
  revocationEndpoint: 'https://oauth2.googleapis.com/revoke',
}

export namespace AuthGoogleoauth {
  /** Google-specific options. Extends `AuthoauthProvider.IOptionsBase`. */
  export interface IOptions<Profile = unknown> extends AuthoauthProvider.IOptionsBase<Profile> {
    /** Default `['openid', 'email', 'profile']`. */
    scopes?: string[]
  }
}

/** Google oauth 2.0 / OIDC provider. */
export function authGoogle<Profile = unknown>(
  opts: AuthGoogleoauth.IOptions<Profile>,
): AuthProvider.IProvider<AuthoauthProvider.IBeginInput, AuthoauthProvider.ICompleteInput, Profile> {
  const client = new AuthoauthClient({
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
        throw new AuthError('AUTH_PROVIDER_FAILED', {
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
