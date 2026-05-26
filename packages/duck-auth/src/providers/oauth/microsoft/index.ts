/**
 * @packageDocumentation
 * Microsoft Entra ID (formerly Azure AD) OAuth 2.0 / OIDC provider.
 * The v2.0 multi-tenant endpoints support both personal Microsoft
 * accounts and work / school accounts; consumers narrow to single-
 * tenant via the `tenant` option.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Provider } from '../../../core/types/provider'
import { OAuthClient, type OAuthEndpoints } from '../core/client'
import { type OAuthBeginInput, type OAuthCompleteInput, type OAuthOptionsBase, oauthProvider } from '../core/provider'

function endpointsFor(tenant: string): OAuthEndpoints {
  return {
    authorizationEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    userinfoEndpoint: 'https://graph.microsoft.com/oidc/userinfo',
  }
}

/**
 * Microsoft Entra ID-specific options.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface MicrosoftOAuthOptions<Profile = unknown> extends OAuthOptionsBase<Profile> {
  /**
   * Tenant: `common` (any AAD tenant + personal accounts), `organizations`
   * (any AAD tenant, no personal), `consumers` (personal only), or a
   * specific tenant GUID. Default `common`.
   */
  tenant?: string
  /** Default `['openid', 'profile', 'email', 'User.Read']`. */
  scopes?: string[]
}

/**
 * Microsoft Entra ID OIDC provider factory.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function microsoft<Profile = unknown>(
  opts: MicrosoftOAuthOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
  const tenant = opts.tenant ?? 'common'
  const endpoints = endpointsFor(tenant)
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints,
    scopes: opts.scopes ?? ['openid', 'profile', 'email', 'User.Read'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
  })
  return oauthProvider<Profile>({
    providerId: 'microsoft',
    client,
    endpoints,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens, c) {
      const info = (await c.userinfo(tokens.access_token)) as {
        sub: string
        email?: string
        name?: string
        picture?: string
      }
      const out: {
        sub: string
        email?: string
        emailVerified?: boolean
        name?: string
        avatarUrl?: string
      } = { sub: info.sub }
      if (info.email !== undefined) {
        out.email = info.email
        // Entra ID userinfo does not return an email_verified claim;
        // Microsoft only returns work / school / Microsoft-account
        // emails post-tenant-config, all of which are pre-verified.
        out.emailVerified = true
      }
      if (info.name !== undefined) out.name = info.name
      if (info.picture !== undefined) out.avatarUrl = info.picture
      return out
    },
  })
}

/**
 * Namespace merge for `MicrosoftOAuth`. Co-locates the flat option type
 * alongside the factory.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace MicrosoftOAuth {
  /** Alias for `MicrosoftOAuthOptions`. */
  export type IOptions = MicrosoftOAuthOptions
}
