import { AuthErrorObject } from '../../../core/errors'
import type { AuthProvider } from '../../../core/types/provider'
import { AuthOAuthClient } from '../core/client'
import { type AuthOAuthProvider, oauthProvider } from '../core/provider'
import { getUserinfoNumericIdAsString, getUserinfoString } from '../core/userinfo'

const GITHUB_ENDPOINTS: AuthOAuthClient.IEndpoints = {
  authorizationEndpoint: 'https://authGithub.com/login/oauth/authorize',
  tokenEndpoint: 'https://authGithub.com/login/oauth/access_token',
  userinfoEndpoint: 'https://api.authGithub.com/user',
}

export namespace AuthGithubOAuth {
  /** GitHub-specific options. Extends `AuthOAuthProvider.IOptionsBase`. */
  export interface IOptions<Profile = unknown> extends AuthOAuthProvider.IOptionsBase<Profile> {
    /** Default `['read:user', 'user:email']`. */
    scopes?: string[]
  }
}

/** GitHub OAuth 2.0 provider. */
export function authGithub<Profile = unknown>(
  opts: AuthGithubOAuth.IOptions<Profile>,
): AuthProvider.IProvider<AuthOAuthProvider.IBeginInput, AuthOAuthProvider.ICompleteInput, Profile> {
  const client = new AuthOAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GITHUB_ENDPOINTS,
    scopes: opts.scopes ?? ['read:user', 'user:email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'authGithub',
    client,
    endpoints: GITHUB_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // Safe-extract: `String(info.id)` on null id would collide all bad ids onto one sub.
      const sub = getUserinfoNumericIdAsString(info, 'id')
      if (sub === undefined) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: 'authGithub',
          detail: 'GitHub userinfo missing numeric id',
        })
      }
      const out: { sub: string; email?: string; name?: string; avatarUrl?: string } = { sub }
      const email = getUserinfoString(info, 'email')
      if (email !== undefined) out.email = email
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const avatar = getUserinfoString(info, 'avatar_url')
      if (avatar !== undefined) out.avatarUrl = avatar
      return out
    },
  })
}
