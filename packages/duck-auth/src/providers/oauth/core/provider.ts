import type { Identity } from '~/core'
import { toCredentialUpsert } from '~/core/credential-utils'
import { sha256 } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/provider/provider.types'
import type { OAuth } from './oauth.types'
import { generatePkce } from './pkce'
import { authBuildState, authVerifyState, signState } from './state'

/**
 * Generic oauth provider. Specific provider modules (authGoogle, authGithub,
 * ...) pre-fill endpoints + scopes + fetchProfile and re-export.
 */
export function oProvider<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: OAuth.Options<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  const fullProviderId = `oauth:${opts.providerId}`
  // Refuse a malformed `redirectUri` at construction so a misconfigured
  // value (e.g. `javascript:alert(1)`, an unparseable string, or one carrying
  // CR/LF for header injection) cannot reach the IdP authorize URL or our
  // session-issue path.
  if (!isValidoauthRedirectUri(opts.redirectUri)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `oauth.redirectUri must be an http(s) URL with no CR/LF (got: ${typeof opts.redirectUri})`,
    })
  }
  return {
    id: fullProviderId,
    kind: 'oauth',
    async begin(_ctx, input) {
      const pkce = generatePkce()
      const statePayload = authBuildState(fullProviderId, pkce.verifier, {
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
      // 2KB cap on `code` prevents outbound-amplification to the IdP.
      if (typeof input.code !== 'string' || input.code.length === 0 || input.code.length > 2048) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: fullProviderId,
          detail: 'invalid authorization code',
        })
      }
      const verified = authVerifyState(input.state, opts.stateSigningSecret)
      if (!verified) {
        throw new AuthError('AUTH_OAUTH_STATE_MISMATCH')
      }
      if (verified.providerId !== fullProviderId) {
        throw new AuthError('AUTH_OAUTH_STATE_MISMATCH')
      }

      const tokens = await opts.client.exchangeCode({
        code: input.code,
        redirectUri: opts.redirectUri,
        codeVerifier: verified.verifier,
      })
      const profile = await opts.fetchProfile(tokens, opts.client)
      if (!profile.sub || profile.sub.length === 0) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: fullProviderId,
          detail: 'oauth profile missing sub',
        })
      }

      let identityId: string | null = null
      if (opts.onSignIn) {
        const r = await opts.onSignIn({
          profile,
          findByProviderSub: (sub) => ctx.stores.identities.findByProviderSub(fullProviderId, sub),
          findByEmail: (email) => ctx.stores.identities.findByEmail(email),
          createIdentity: async (p) => {
            const created = await ctx.stores.identities.create({
              profile: p,
              providers: [{ providerId: fullProviderId, providerSub: profile.sub, addedAt: new Date() }],
              emailVerified: false,
            })
            return { id: created.id }
          },
          linkProvider: async (id, sub) => {
            await ctx.stores.identities.link(id, { providerId: fullProviderId, providerSub: sub, addedAt: new Date() })
          },
        })
        if (!r) {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId: fullProviderId,
            detail: 'sign-in refused by onSignIn callback',
          })
        }
        identityId = r.identityId
      } else {
        const bySub = await ctx.stores.identities.findByProviderSub(fullProviderId, profile.sub)
        if (bySub) {
          identityId = bySub.id
        } else if (profile.email) {
          const byEmail = await ctx.stores.identities.findByEmail(profile.email)
          if (byEmail) {
            // Email matches but no sub link; silent auto-link is ATO bait.
            const policy = opts.onFederationConflict ?? 'reject'
            const verdict = await resolveFederationConflict(policy, {
              existingIdentityId: byEmail.id,
              profile,
              providerId: fullProviderId,
            })
            if (verdict === 'reject') {
              throw new AuthError('AUTH_PROVIDER_FAILED', {
                providerId: fullProviderId,
                detail:
                  'federation-conflict: an existing identity owns this email; provider-sub link refused under the configured policy',
              })
            }
            await ctx.stores.identities.link(byEmail.id, {
              providerId: fullProviderId,
              providerSub: profile.sub,
              addedAt: new Date(),
            })
            identityId = byEmail.id
          }
        }
        if (!identityId) {
          const projected = opts.profileToIdentityProfile?.(profile)
          if (!projected) {
            throw new AuthError('AUTH_PROVIDER_FAILED', {
              providerId: fullProviderId,
              detail: 'profileToIdentityProfile rejected the profile',
            })
          }
          const created = await ctx.stores.identities.create({
            profile: projected,
            providers: [{ providerId: fullProviderId, providerSub: profile.sub, addedAt: new Date() }],
            emailVerified: false,
          })
          identityId = created.id
        }
      }

      if (tokens.refresh_token) {
        const familyId = `${fullProviderId}:${profile.sub}:${sha256(input.code).slice(0, 16)}`
        await ctx.stores.credentials.upsert(
          toCredentialUpsert({
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
            } satisfies OAuth.CredentialMetadata,
          }),
          ctx.tenant,
        )
      }

      return [
        {
          type: 'startSession',
          identityId,
          factors: [{ method: 'oauth', completedAt: new Date() }],
          aal: 1,
        },
      ]
    },
  }
}

/**
 * Resolve a federation-conflict policy to a `'link' | 'reject'`
 * verdict. Kept module-local so callers cannot bypass the
 * `'link-if-verified'` semantics (which require BOTH
 * `profile.emailVerified === true` AND an unambiguous email match).
 */
async function resolveFederationConflict(
  policy: OAuth.FederationPolicy,
  ctx: { existingIdentityId: string; profile: OAuth.Profile; providerId: string },
): Promise<'link' | 'reject'> {
  if (policy === 'reject') return 'reject'
  if (policy === 'link-if-verified') {
    return ctx.profile.emailVerified === true ? 'link' : 'reject'
  }
  // Operator-supplied callback. Refuse anything other than the documented
  // {'link' | 'reject'} discriminator so a buggy/typo'd return doesn't
  // accidentally fall-through to 'link' (the dangerous default).
  const verdict = await policy(ctx)
  return verdict === 'link' ? 'link' : 'reject'
}

function isValidoauthRedirectUri(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > 2048) return false
  if (value.includes('\r') || value.includes('\n')) return false
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return false
  }
  return parsed.protocol === 'https:' || parsed.protocol === 'http:'
}
