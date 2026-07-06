import type { Identity } from '../../core'
import { AuthError } from '../../core/errors'
import type { ApiKeysFacet } from '../../core/facets/apikeys'
import type { Provider } from '../../core/types/provider'

export namespace AuthApiKeyProvider {
  /** Config knobs for {@link authApiKey}. */
  export interface IOptions {
    /** Bound `ApiKeysFacet`. Provider delegates verify + scope checks. */
    apiKeys: ApiKeysFacet
    /** Per-key rate-limit key prefix. Default `signin:api-key:`. */
    limiterKeyPrefix?: string
    /**
     * Scopes every request must hold. Use sparingly; per-route scope
     * checks should call `apiKeys.requireScopes(scopes, [...])`.
     */
    requireScopes?: string[]
  }

  /** Input to begin (no-op for api-key). */
  export interface IBeginInput {
    hint?: never
  }

  /** Input to complete. */
  export interface ICompleteInput {
    /** Plaintext key (`ak_live_...`). */
    token: string
  }
}

/**
 * `api-key` provider - bearer-style sign-in for service-to-service
 * callers. The provider verifies the plaintext token via `ApiKeysFacet`,
 * applies the configured per-key rate-limit, and emits a `startSession`
 * Intent with `kind: 'apikey'` + `aal: 1`.
 */
export function authApiKey<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: AuthApiKeyProvider.IOptions,
): Provider.Me<AuthApiKeyProvider.IBeginInput, AuthApiKeyProvider.ICompleteInput, Profile> {
  const prefix = opts.limiterKeyPrefix ?? 'signin:api-key:'
  return {
    id: 'api-key',
    kind: 'api-key',

    async begin(): Promise<Provider.Intent[]> {
      return []
    },

    async complete(ctx, input): Promise<Provider.InternalIntent[]> {
      // typeof-guard prevents sha256(non-string) throwing TypeError before the
      // rate limiter can fire (caller would see 500 instead of 401, plus the
      // call would bypass the per-token brute-force quota).
      if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 512) {
        throw new AuthError('AUTH_APIKEY_INVALID')
      }
      const keyHash = ctx.crypto.authSha256(input.token).slice(0, 16)
      const rl = await ctx.limiter.consume(`${prefix}${keyHash}`)
      if (!rl.ok) {
        throw new AuthError('AUTH_RATE_LIMITED', {
          retryAfter: Math.max(1, Math.ceil((rl.resetAt.getTime() - Date.now()) / 1000)),
        })
      }
      const verified = await opts.apiKeys.verify(input.token, ctx.tenant)
      // A tenant-bound api-key must NOT identify-confirm on a different (or empty)
      // tenant scope; otherwise the resulting session lacks the key's tenancy
      // while the caller still holds proof-of-key for that tenant.
      if (verified.tenantId !== undefined && ctx.tenant.tenantId !== verified.tenantId) {
        throw new AuthError('AUTH_APIKEY_INVALID')
      }
      if (opts.requireScopes && opts.requireScopes.length > 0) {
        opts.apiKeys.requireScopes(verified.scopes, opts.requireScopes)
      }
      return [
        {
          type: 'startSession',
          identityId: verified.identityId,
          factors: [{ method: 'api-key', completedAt: new Date() }],
          aal: 1,
        },
      ]
    },
  }
}
