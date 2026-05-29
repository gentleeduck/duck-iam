/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { PasswordsFacet } from '../../core/facets/passwords'
import type { Provider } from '../../core/types/provider'

/**
 * Password provider - email + password sign-in. Operates against the
 * configured PasswordsFacet so hashing/strength rules live in one place.
 *
 * `begin` is a no-op because password flow has no challenge round-trip.
 * `complete` validates input + rate-limits per email + verifies + emits
 * a `startSession` Intent that the framework adapter turns into a real
 * session via SessionsFacet.rotateOrCreate({ purpose: 'signin' }).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface PasswordProviderOptions {
  /**
   * Function the provider uses to find an identity given an email.
   * Required because the provider doesn't import AuthRoot directly.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
  /** Bound PasswordsFacet - verify + needsRehash + slow rehash. */
  passwords: PasswordsFacet
  /** Per-email rate-limit key prefix. Default 'signin:password:'. */
  limiterKeyPrefix?: string
  /** Optional autoRehash on successful verify when needsRehash=true. Default true. */
  autoRehash?: boolean
}

export interface PasswordBeginInput {
  email: string
}

export interface PasswordCompleteInput {
  email: string
  password: string
}

/**
 * `password`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function password<Profile = unknown>(
  opts: PasswordProviderOptions,
): Provider.IProvider<PasswordBeginInput, PasswordCompleteInput, Profile> {
  const prefix = opts.limiterKeyPrefix ?? 'signin:password:'
  const autoRehash = opts.autoRehash ?? true
  return {
    id: 'password',
    kind: 'password',
    async begin(_ctx, _input) {
      // Password sign-in has no async challenge round-trip; UI submits both
      // email + password in one shot. Returning [] keeps the framework
      // adapter happy when the route exists but the flow is single-step.
      return []
    },
    async complete(ctx, input) {
      const { email, password: pw } = input
      if (typeof email !== 'string' || typeof pw !== 'string' || email.length === 0 || pw.length === 0) {
        throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
      }

      // Rate-limit per email AND per IP (composite recommended; framework adapter
      // exposes ip via ctx in a follow-up patch). v0.1 keys on email only.
      const limitKey = `${prefix}${email.toLowerCase()}`
      const limited = await ctx.limiter.consume(limitKey)
      if (!limited.ok) {
        throw new AuthErrorObject('AUTH/RATE_LIMITED', {
          retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
        })
      }

      const identity = await opts.findIdentityByEmail(email, ctx.tenant.tenantId)
      // ALWAYS run verify (even with no matching identity) to keep timing constant.
      const verifyResult = identity
        ? await opts.passwords.verify(identity.id, pw, ctx.tenant)
        : await opts.passwords.verify('__never__', pw, ctx.tenant)

      if (!identity || !verifyResult.ok) {
        await ctx.events.emit('signin.failed', { providerId: 'password', reason: 'invalid-credentials' })
        // Generic 401 - never leaks which side failed.
        throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
      }

      if (autoRehash && verifyResult.ok && verifyResult.needsRehash) {
        // Best-effort; never blocks the signin response.
        void opts.passwords.rehash(identity.id, pw, ctx.tenant).catch(() => {})
      }

      const now = Date.now()
      return [
        {
          type: 'startSession',
          identityId: identity.id,
          factors: [{ method: 'password', completedAt: now }],
          aal: 1,
        },
      ]
    },
  }
}

/**
 * Namespace merge for PasswordProvider. Co-locates the config + input +
 * output shapes via TS namespace declaration. Consumers can write either
 * the flat name (PasswordProviderOptions) or the namespaced form
 * (PasswordProvider.IOptions); both resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace PasswordProvider {
  /** Alias for the flat `PasswordProviderOptions` type. */
  export type IOptions = PasswordProviderOptions
  /** Alias for the flat `PasswordBeginInput` type. */
  export type IBeginInput = PasswordBeginInput
  /** Alias for the flat `PasswordCompleteInput` type. */
  export type ICompleteInput = PasswordCompleteInput
}
