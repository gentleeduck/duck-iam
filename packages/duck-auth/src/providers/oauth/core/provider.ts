/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { sha256 } from '../../../core/crypto'
import { AuthErrorObject } from '../../../core/errors'
import type { Provider } from '../../../core/types/provider'
import type { OAuthClient, OAuthEndpoints } from './client'
import { generatePkce } from './pkce'
import { buildState, signState, verifyState } from './state'

/**
 * Canonical profile shape after a provider extracts it from userinfo /
 * id_token / provider-specific endpoint. Providers (google, github, ...)
 * map their idiosyncratic field names to this shape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OAuthProfile {
  /** Stable subject identifier at the provider (OIDC `sub`). */
  sub: string
  email?: string
  emailVerified?: boolean
  name?: string
  avatarUrl?: string
}

/**
 * Shared option surface every provider-specific OAuth options interface
 * (Google / GitHub / Apple / Discord / ...) extends. Keeps consumer call
 * sites identical across providers + gives library a single place to
 * evolve cross-provider knobs (DPoP, PKCE relaxation, etc.).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OAuthOptionsBase<Profile = unknown> {
  /** OAuth client id assigned by the IdP. */
  clientId: string
  /** Client secret. Confidential clients (server-side) only. */
  clientSecret: string
  /** Exact callback URL registered with the IdP. Must match. */
  redirectUri: string
  /** Per-AuthRoot signing secret for the OAuth `state` parameter. */
  stateSigningSecret: string
  /** Override IdP scopes; falls back to provider default. */
  scopes?: string[]
  /** Override fetch impl (test stubs). */
  fetch?: typeof globalThis.fetch
  /** Customise identity resolution at signin time. */
  onSignIn?: OAuthProviderOptions<Profile>['onSignIn']
  /** Project canonical OAuthProfile into the consumer's Profile shape. */
  profileToIdentityProfile?: OAuthProviderOptions<Profile>['profileToIdentityProfile']
}

export interface OAuthProviderOptions<Profile = unknown> {
  /** Stable id; library prefixes with `oauth:` for consistency. */
  providerId: string
  client: OAuthClient
  endpoints: OAuthEndpoints | (() => Promise<OAuthEndpoints>)
  /** Redirect URI registered with the provider - must be exact match. */
  redirectUri: string
  /** Secret used to sign the OAuth `state` parameter. */
  stateSigningSecret: string
  /** Extract a canonical profile from the token response + provider userinfo. */
  fetchProfile: (tokens: { access_token: string; id_token?: string }, client: OAuthClient) => Promise<OAuthProfile>
  /** Map a canonical OAuth profile to the consumer's Profile shape on first sign-in. */
  profileToIdentityProfile?: (p: OAuthProfile) => Profile
  /**
   * Optional: receive the canonical profile + existing identity match (by sub)
   * and decide which identity to log in. Returns null to refuse the sign-in.
   * Default: find-by-sub, else find-by-email + auto-link, else auto-create.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  onSignIn?: (ctx: {
    profile: OAuthProfile
    findByProviderSub: (providerSub: string) => Promise<{ id: string } | null>
    findByEmail: (email: string) => Promise<{ id: string } | null>
    createIdentity: (profile: Profile) => Promise<{ id: string }>
    linkProvider: (identityId: string, providerSub: string) => Promise<void>
  }) => Promise<{ identityId: string } | null>
}

export interface OAuthBeginInput {
  /** Optional return-to path; the library appends to the front-end after callback. */
  returnTo?: string
}

export interface OAuthCompleteInput {
  /** Authorisation code returned by the provider. */
  code: string
  /** Opaque state value the library issued at begin. */
  state: string
}

/**
 * Generic OAuth provider. Specific provider modules (google, github)
 * pre-fill endpoints + scopes + fetchProfile and re-export.
 *
 * Refresh-token reuse detection is documented at DESIGN section 4; the
 * persistence half lives in the credentials store under
 * `kind: 'oauth'` + `metadata.familyId / generation / replayedAt`.
 * v0.2 wires the auto-detect-on-refresh flow into FlowsFacet; for v0.1
 * each provider stores the refresh token + family id so reuse
 * detection logic can be added without a schema migration.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function oauthProvider<Profile = unknown>(
  opts: OAuthProviderOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
  const fullProviderId = `oauth:${opts.providerId}`
  return {
    id: fullProviderId,
    kind: 'oauth',
    async begin(ctx, input) {
      const pkce = generatePkce()
      const statePayload = buildState(fullProviderId, pkce.verifier, {
        ...(input?.returnTo !== undefined && { returnTo: input.returnTo }),
      })
      const state = signState(statePayload, opts.stateSigningSecret)
      const url = await opts.client.buildAuthorizeUrl({
        redirectUri: opts.redirectUri,
        state,
        codeChallenge: pkce.challenge,
      })
      return [{ type: 'redirect', url, status: 302 }]
    },
    async complete(ctx, input) {
      const verified = verifyState(input.state, opts.stateSigningSecret)
      if (!verified) {
        throw new AuthErrorObject('AUTH/OAUTH_STATE_MISMATCH')
      }
      if (verified.providerId !== fullProviderId) {
        throw new AuthErrorObject('AUTH/OAUTH_STATE_MISMATCH')
      }

      const tokens = await opts.client.exchangeCode({
        code: input.code,
        redirectUri: opts.redirectUri,
        codeVerifier: verified.verifier,
      })
      const profile = await opts.fetchProfile(tokens, opts.client)
      if (!profile.sub || profile.sub.length === 0) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: fullProviderId,
          detail: 'oauth profile missing sub',
        })
      }

      // Identity resolution
      let identityId: string | null = null
      if (opts.onSignIn) {
        const r = await opts.onSignIn({
          profile,
          findByProviderSub: (sub) => ctx.stores.identities.findByProviderSub(fullProviderId, sub, ctx.tenant),
          findByEmail: (email) => ctx.stores.identities.findByEmail(email, ctx.tenant),
          createIdentity: async (p) => {
            const created = await ctx.stores.identities.create(
              {
                profile: p,
                providers: [{ providerId: fullProviderId, providerSub: profile.sub, addedAt: Date.now() }],
              },
              ctx.tenant,
            )
            return { id: created.id }
          },
          linkProvider: async (id, sub) => {
            await ctx.stores.identities.link(
              id,
              { providerId: fullProviderId, providerSub: sub, addedAt: Date.now() },
              ctx.tenant,
            )
          },
        })
        if (!r) {
          throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
            providerId: fullProviderId,
            detail: 'sign-in refused by onSignIn callback',
          })
        }
        identityId = r.identityId
      } else {
        const bySub = await ctx.stores.identities.findByProviderSub(fullProviderId, profile.sub, ctx.tenant)
        if (bySub) {
          identityId = bySub.id
        } else if (profile.email) {
          const byEmail = await ctx.stores.identities.findByEmail(profile.email, ctx.tenant)
          if (byEmail) {
            await ctx.stores.identities.link(
              byEmail.id,
              { providerId: fullProviderId, providerSub: profile.sub, addedAt: Date.now() },
              ctx.tenant,
            )
            identityId = byEmail.id
          }
        }
        if (!identityId) {
          const projected =
            opts.profileToIdentityProfile?.(profile) ??
            ({ email: profile.email, name: profile.name } as unknown as Profile)
          const created = await ctx.stores.identities.create(
            {
              profile: projected,
              providers: [{ providerId: fullProviderId, providerSub: profile.sub, addedAt: Date.now() }],
            },
            ctx.tenant,
          )
          identityId = created.id
        }
      }

      // Persist tokens + family id for reuse detection (RFC 6749 section 10.4).
      if (tokens.refresh_token) {
        const familyId = `${fullProviderId}:${profile.sub}:${sha256(input.code).slice(0, 16)}`
        await ctx.stores.credentials.upsert(
          {
            identityId,
            kind: 'oauth',
            secret: sha256(tokens.refresh_token),
            metadata: {
              provider: fullProviderId,
              sub: profile.sub,
              familyId,
              generation: 1,
              accessToken: tokens.access_token,
              accessTokenExpiresAt: tokens.expires_in !== undefined ? Date.now() + tokens.expires_in * 1000 : undefined,
            },
          },
          ctx.tenant,
        )
      }

      return [
        {
          type: 'startSession',
          identityId,
          factors: [{ method: 'oauth', completedAt: Date.now() }],
          aal: 1,
        },
      ]
    },
  }
}
