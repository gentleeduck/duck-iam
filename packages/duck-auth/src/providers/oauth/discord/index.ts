/**
 * @packageDocumentation
 * Discord OAuth 2.0 provider. Discord does not implement OIDC; the
 * provider hits `/users/@me` directly to derive sub + email + avatar.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Provider } from '../../../core/types/provider'
import { OAuthClient, type OAuthEndpoints } from '../core/client'
import { type OAuthBeginInput, type OAuthCompleteInput, type OAuthOptionsBase, oauthProvider } from '../core/provider'

const DISCORD_ENDPOINTS: OAuthEndpoints = {
  authorizationEndpoint: 'https://discord.com/oauth2/authorize',
  tokenEndpoint: 'https://discord.com/api/oauth2/token',
  userinfoEndpoint: 'https://discord.com/api/users/@me',
  revocationEndpoint: 'https://discord.com/api/oauth2/token/revoke',
}

/** Discord-specific options. */
export interface DiscordOAuthOptions<Profile = unknown> extends OAuthOptionsBase<Profile> {
  /** Default `['identify', 'email']`. */
  scopes?: string[]
}

/**
 * Discord OAuth 2.0 provider factory. Maps the Discord `/users/@me`
 * response into the shared OAuthProfile shape; avatar is rebuilt from
 * `${id}/${avatar}.png` per the Discord CDN convention.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function discord<Profile = unknown>(
  opts: DiscordOAuthOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: DISCORD_ENDPOINTS,
    scopes: opts.scopes ?? ['identify', 'email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'discord',
    client,
    endpoints: DISCORD_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = (await c.userinfo(tokens.access_token)) as {
        id: string
        username?: string
        global_name?: string
        email?: string
        verified?: boolean
        avatar?: string | null
      }
      const out: {
        sub: string
        email?: string
        emailVerified?: boolean
        name?: string
        avatarUrl?: string
      } = { sub: info.id }
      if (info.email !== undefined) out.email = info.email
      if (info.verified !== undefined) out.emailVerified = info.verified
      const displayName = info.global_name ?? info.username
      if (displayName !== undefined) out.name = displayName
      if (info.avatar) {
        out.avatarUrl = `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.png`
      }
      return out
    },
  })
}

/**
 * Namespace merge for `DiscordOAuth`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace DiscordOAuth {
  /** Alias for `DiscordOAuthOptions`. */
  export type IOptions = DiscordOAuthOptions
}
