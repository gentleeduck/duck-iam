/**
 * Discord OAuth 2.0 provider. Discord does not implement OIDC; the
 * provider hits `/users/@me` directly to derive sub + email + avatar.
 */

import { AuthErrorObject } from '../../../core/errors'
import type { Provider } from '../../../core/types/provider'
import { OAuthClient } from '../core/client'
import { type OAuthProvider, oauthProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const DISCORD_ENDPOINTS: OAuthClient.IEndpoints = {
  authorizationEndpoint: 'https://discord.com/oauth2/authorize',
  tokenEndpoint: 'https://discord.com/api/oauth2/token',
  userinfoEndpoint: 'https://discord.com/api/users/@me',
  revocationEndpoint: 'https://discord.com/api/oauth2/token/revoke',
}

/**
 * Public surface for the Discord OAuth provider. Every type lives
 * inside the namespace.
 */
export namespace DiscordOAuth {
  /** Discord-specific options. */
  export interface IOptions<Profile = unknown> extends OAuthProvider.IOptionsBase<Profile> {
    /** Default `['identify', 'email']`. */
    scopes?: string[]
  }
}

/**
 * Discord OAuth 2.0 provider factory.
 */
export function discord<Profile = unknown>(
  opts: DiscordOAuth.IOptions<Profile>,
): Provider.IProvider<OAuthProvider.IBeginInput, OAuthProvider.ICompleteInput, Profile> {
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
      const info = await c.userinfo(tokens.access_token)
      // safe-extract instead of `as`. Discord
      // user ids are stringified snowflakes; verify the shape rather
      // than trust the cast.
      const sub = getUserinfoString(info, 'id')
      if (sub === undefined) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: 'discord',
          detail: 'Discord userinfo missing id',
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
      if (getUserinfoBooleanTrue(info, 'verified')) out.emailVerified = true
      const displayName = getUserinfoString(info, 'global_name') ?? getUserinfoString(info, 'username')
      if (displayName !== undefined) out.name = displayName
      const avatar = getUserinfoString(info, 'avatar')
      if (avatar !== undefined) {
        out.avatarUrl = `https://cdn.discordapp.com/avatars/${sub}/${avatar}.png`
      }
      return out
    },
  })
}
