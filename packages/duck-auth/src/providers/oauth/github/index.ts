import type { Identity } from '~/core'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/types/provider'
import { OauthClient } from '../core/client'
import { type AuthoProvider, oProvider } from '../core/provider'
import { getUserinfoNumericIdAsString, getUserinfoString } from '../core/userinfo'

const GITHUB_ENDPOINTS: OauthClient.Endpoints = {
  authorizationEndpoint: 'https://authGithub.com/login/oauth/authorize',
  tokenEndpoint: 'https://authGithub.com/login/oauth/access_token',
  userinfoEndpoint: 'https://api.authGithub.com/user',
}

export namespace AuthGithuboauth {
  /** GitHub-specific options. Extends `AuthoProvider.IOptionsBase`. */
  export interface IOptions<Profile = unknown> extends AuthoProvider.IOptionsBase<Profile> {
    /** Default `['read:user', 'user:email']`. */
    scopes?: string[]
  }
}

/** GitHub oauth 2.0 provider. */
export function authGithub<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: AuthGithuboauth.IOptions<Profile>,
): Provider.Me<AuthoProvider.IBeginInput, AuthoProvider.ICompleteInput, Profile> {
  const client = new OauthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GITHUB_ENDPOINTS,
    scopes: opts.scopes ?? ['read:user', 'user:email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oProvider<Profile>({
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
        throw new AuthError('AUTH_PROVIDER_FAILED', {
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
