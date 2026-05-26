/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Provider } from '../../../core/types/provider'
import { OAuthClient, type OAuthEndpoints } from '../core/client'
import { type OAuthBeginInput, type OAuthCompleteInput, type OAuthOptionsBase, oauthProvider } from '../core/provider'

const GITHUB_ENDPOINTS: OAuthEndpoints = {
  authorizationEndpoint: 'https://github.com/login/oauth/authorize',
  tokenEndpoint: 'https://github.com/login/oauth/access_token',
  userinfoEndpoint: 'https://api.github.com/user',
}

/**
 * GitHub-specific OAuth options. Extends the shared `OAuthOptionsBase` so
 * every IdP provider shares the same call-site shape; only IdP-specific
 * fields land here.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface GitHubOAuthOptions<Profile = unknown> extends OAuthOptionsBase<Profile> {
  /** Default `['read:user', 'user:email']`. */
  scopes?: string[]
}

/** GitHub OAuth 2.0 provider. */
export function github<Profile = unknown>(
  opts: GitHubOAuthOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GITHUB_ENDPOINTS,
    scopes: opts.scopes ?? ['read:user', 'user:email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'github',
    client,
    endpoints: GITHUB_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = (await c.userinfo(tokens.access_token)) as {
        id: number
        email?: string | null
        name?: string | null
        avatar_url?: string | null
      }
      const out: { sub: string; email?: string; name?: string; avatarUrl?: string } = {
        sub: String(info.id),
      }
      if (info.email) out.email = info.email
      if (info.name) out.name = info.name
      if (info.avatar_url) out.avatarUrl = info.avatar_url
      return out
    },
  })
}

/**
 * Namespace merge for `GithubOAuth`. Co-locates the flat type exports
 * alongside the primary symbol via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace GithubOAuth {
  /** Alias for the flat `GitHubOAuthOptions` type. */
  export type IGitHubOAuthOptions = GitHubOAuthOptions
}
