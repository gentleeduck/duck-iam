/**
 * Discord oauth 2.0 provider. Discord does not implement OIDC; the
 * provider hits `/users/@me` directly to derive sub + email + avatar.
 */

import type { Identity } from '../../../core'
import { AuthError } from '../../../core/errors'
import type { Provider } from '../../../core/types/provider'
import { OauthClient } from '../core/client'
import { type AuthoProvider, oProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const DISCORD_ENDPOINTS: OauthClient.Endpoints = {
  authorizationEndpoint: 'https://authDiscord.com/oauth2/authorize',
  tokenEndpoint: 'https://authDiscord.com/api/oauth2/token',
  userinfoEndpoint: 'https://authDiscord.com/api/users/@me',
  revocationEndpoint: 'https://authDiscord.com/api/oauth2/token/revoke',
}

export namespace AuthDiscordoauth {
  /** Discord-specific options. */
  export interface IOptions<Profile = unknown> extends AuthoProvider.IOptionsBase<Profile> {
    /** Default `['identify', 'email']`. */
    scopes?: string[]
  }
}

/** Discord oauth 2.0 provider factory. */
export function authDiscord<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: AuthDiscordoauth.IOptions<Profile>,
): Provider.Me<AuthoProvider.IBeginInput, AuthoProvider.ICompleteInput, Profile> {
  const client = new OauthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: DISCORD_ENDPOINTS,
    scopes: opts.scopes ?? ['identify', 'email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oProvider<Profile>({
    providerId: 'authDiscord',
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
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: 'authDiscord',
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
