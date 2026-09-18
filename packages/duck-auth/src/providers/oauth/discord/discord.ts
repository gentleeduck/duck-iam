/** Discord implements no OIDC, so the profile comes from `/users/@me` directly. */

import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { OAuthClient } from '../core/client'
import type { OAuth } from '../core/oauth.types'
import { oProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const DISCORD_ENDPOINTS: OAuth.Endpoints = {
  authorizationEndpoint: 'https://discord.com/oauth2/authorize',
  tokenEndpoint: 'https://discord.com/api/oauth2/token',
  userinfoEndpoint: 'https://discord.com/api/users/@me',
  revocationEndpoint: 'https://discord.com/api/oauth2/token/revoke',
}

/** Discord OAuth provider. */
export function discord<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: OAuth.DiscordOptions<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  const client = new OAuthClient({
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
    ...(opts.onFederationConflict !== undefined && { onFederationConflict: opts.onFederationConflict }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // Discord user ids are stringified snowflakes, so the shape is verified rather than asserted.
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
