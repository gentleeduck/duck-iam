import type { Identity } from '~/core'
import { randomToken, sha256 } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Provider } from '~/core/provider/provider.types'
import { toApiKeysConfig } from './api-key.config'
import { ApiKeysFacet } from './api-key.facet'
import type { ApiKeys } from './api-key.types'

/**
 * `api-key` sign-in provider - bearer-style sign-in for service-to-service
 * callers. The provider verifies the plaintext token via `ApiKeysFacet`,
 * applies the configured per-key rate-limit, and emits a `startSession`
 * Intent with `kind: 'api-key'` + `aal: 1`.
 */
export function authApiKey<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: ApiKeys.Options,
): Provider.Me<ApiKeys.BeginInput, ApiKeys.CompleteInput, Profile> {
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

/**
 * API-key capability module (mechanism A). Owns the ApiKeysFacet + its config
 * and mounts it onto the engine at construction, exposing `auth.apiKeys`.
 * Add it to `providers: [apiKeyProvider()]`.
 *
 * The bearer *sign-in* provider ({@link authApiKey}) is registered separately
 * by the app, since it binds to the mounted facet + app-specific scope rules.
 */
export function apiKeyProvider<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: ApiKeys.ConfigInput): Provider.ProviderModule<Profile, Tenant, OrgMeta> {
  return {
    name: 'api-key',
    attach(engine) {
      engine.setApiKeys(
        new ApiKeysFacet(
          engine.config.stores.credentials,
          engine.events,
          { randomToken, sha256 },
          toApiKeysConfig(cfg),
        ),
      )
    },
  }
}
