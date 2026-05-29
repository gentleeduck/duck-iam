import { AuthErrorObject } from '../../core/errors'
import type { PasswordsFacet } from '../../core/facets/passwords'
import type { Provider } from '../../core/types/provider'

/**
 * Public surface for the password provider. Every type lives inside
 * the namespace.
 */
export namespace PasswordProvider {
  /** Config knobs for {@link password}. */
  export interface IOptions {
    /** Function to find an identity given an email. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /** Bound PasswordsFacet - verify + needsRehash + slow rehash. */
    passwords: PasswordsFacet
    /** Per-email rate-limit key prefix. Default 'signin:password:'. */
    limiterKeyPrefix?: string
    /** Auto-rehash on successful verify when needsRehash=true. Default true. */
    autoRehash?: boolean
  }

  /** Input to begin (unused for password but kept for parity). */
  export interface IBeginInput {
    email: string
  }

  /** Input to complete. */
  export interface ICompleteInput {
    email: string
    password: string
  }
}

/**
 * Password provider - email + password sign-in. Operates against the
 * configured PasswordsFacet so hashing/strength rules live in one
 * place.
 *
 * `begin` is a no-op; password flow has no challenge round-trip.
 * `complete` validates input + rate-limits per email + verifies + emits
 * a `startSession` Intent.
 */
export function password<Profile = unknown>(
  opts: PasswordProvider.IOptions,
): Provider.IProvider<PasswordProvider.IBeginInput, PasswordProvider.ICompleteInput, Profile> {
  const prefix = opts.limiterKeyPrefix ?? 'signin:password:'
  const autoRehash = opts.autoRehash ?? true
  return {
    id: 'password',
    kind: 'password',
    async begin(_ctx, _input) {
      return []
    },
    async complete(ctx, input) {
      const { email, password: pw } = input
      // email cap per RFC 5321 (254); password cap matches the
      // PasswordsFacet maxLength (default 1024). Without caps, an
      // attacker can DoS via huge inputs reaching the hasher / store.
      if (
        typeof email !== 'string' ||
        typeof pw !== 'string' ||
        email.length === 0 ||
        email.length > 254 ||
        pw.length === 0 ||
        pw.length > 1024
      ) {
        throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
      }

      // Canonical (trim + lowercase) email so the rate-limit bucket AND
      // the identity lookup share one key. If the operator wires
      // findIdentityByEmail without internal case-folding, raw `email`
      // would let `A@x.com` and `a@x.com` register/sign-in as distinct
      // accounts.
      const emailCanonical = email.trim().toLowerCase()
      const limitKey = `${prefix}${emailCanonical}`
      const limited = await ctx.limiter.consume(limitKey)
      if (!limited.ok) {
        throw new AuthErrorObject('AUTH/RATE_LIMITED', {
          retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
        })
      }

      const identity = await opts.findIdentityByEmail(emailCanonical, ctx.tenant.tenantId)
      // ALWAYS run verify (even with no matching identity) to keep timing constant.
      const verifyResult = identity
        ? await opts.passwords.verify(identity.id, pw, ctx.tenant)
        : await opts.passwords.verify('__never__', pw, ctx.tenant)

      if (!identity || !verifyResult.ok) {
        await ctx.events.emit('signin.failed', { providerId: 'password', reason: 'invalid-credentials' })
        throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
      }

      if (autoRehash && verifyResult.ok && verifyResult.needsRehash) {
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
