/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { ApiKeysFacet } from '../../core/facets/apikeys'
import type { Provider } from '../../core/types/provider'

/**
 * Configuration for the `api-key` sign-in provider.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface ApiKeyProviderOptions {
  /** Bound `ApiKeysFacet`. The provider delegates verify + scope checks. */
  apiKeys: ApiKeysFacet
  /** Per-key rate-limit key prefix. Default `signin:api-key:`. */
  limiterKeyPrefix?: string
  /**
   * Scopes every request must hold. Use sparingly; per-route scope
   * checks should call `apiKeys.requireScopes(scopes, [...])` instead.
   */
  requireScopes?: string[]
}

export interface ApiKeyBeginInput {
  /** No-op; api-key has no challenge round-trip. Kept for surface parity. */
  hint?: never
}

export interface ApiKeyCompleteInput {
  /** Plaintext key (`ak_live_...`); typically carried in `X-Api-Key` or `Authorization: Bearer ...`. */
  token: string
}

/**
 * `api-key` provider - bearer-style sign-in for service-to-service
 * callers. The provider verifies the plaintext token via `ApiKeysFacet`,
 * applies the configured per-key rate-limit, and emits a `startSession`
 * Intent with `kind: 'apikey'` + `aal: 1` (api-key auth is single-factor
 * by definition).
 *
 * Sign-in surface:
 *   - begin: no-op; api-key flows have no challenge round-trip
 *   - complete: hashes the plaintext + delegates to ApiKeysFacet.verify;
 *     applies rate-limit; emits startSession with the resolved
 *     identityId + factor `api-key`
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function apiKey<Profile = unknown>(
  opts: ApiKeyProviderOptions,
): Provider.IProvider<ApiKeyBeginInput, ApiKeyCompleteInput, Profile> {
  const prefix = opts.limiterKeyPrefix ?? 'signin:api-key:'
  return {
    id: 'api-key',
    kind: 'api-key',

    async begin(): Promise<Provider.Intent[]> {
      return []
    },

    async complete(ctx, input): Promise<Provider.Intent[]> {
      if (!input.token) {
        throw new AuthErrorObject('AUTH/APIKEY_INVALID')
      }
      // Rate-limit per-key (sha-256 the token so we never hand a plaintext
      // identifier to the limiter store).
      const keyHash = ctx.crypto.sha256(input.token).slice(0, 16)
      const rl = await ctx.limiter.consume(`${prefix}${keyHash}`)
      if (!rl.ok) {
        throw new AuthErrorObject('AUTH/RATE_LIMITED', {
          retryAfter: Math.max(1, Math.ceil((rl.resetAt - Date.now()) / 1000)),
        })
      }
      const verified = await opts.apiKeys.verify(input.token, ctx.tenant)
      if (opts.requireScopes && opts.requireScopes.length > 0) {
        opts.apiKeys.requireScopes(verified.scopes, opts.requireScopes)
      }
      void verified.keyId
      return [
        {
          type: 'startSession',
          identityId: verified.identityId,
          factors: [{ method: 'api-key', completedAt: Date.now() }],
          aal: 1,
        },
      ]
    },
  }
}

/**
 * Namespace merge for the `api-key` provider exports. Co-locates the
 * options + input/output shapes alongside the factory.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ApiKeyProvider {
  /** Alias for `ApiKeyProviderOptions`. */
  export type IOptions = ApiKeyProviderOptions
  /** Alias for `ApiKeyBeginInput`. */
  export type IBeginInput = ApiKeyBeginInput
  /** Alias for `ApiKeyCompleteInput`. */
  export type ICompleteInput = ApiKeyCompleteInput
}
