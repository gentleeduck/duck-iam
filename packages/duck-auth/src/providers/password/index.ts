import { AuthError } from '../../core/errors'
import type { PasswordsFacet } from '../../core/facets/passwords'
import type { AuthProvider } from '../../core/types/provider'

/**
 * Sentinel identity id fed to `verify` on the no-such-user branch to keep
 * timing constant (defeats account enumeration). MUST be a syntactically
 * valid UUID: the SQL adapters store `identity_id` as a `uuid` column, so a
 * non-UUID sentinel (e.g. `'__never__'`) makes Postgres throw
 * `invalid input syntax for type uuid` instead of returning zero rows. The
 * all-zero UUID is well-formed and matches no real identity.
 */
const NO_IDENTITY_SENTINEL = '00000000-0000-0000-0000-000000000000'

export namespace AuthPasswordProvider {
  /** Config knobs for {@link authPassword}. */
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

  /** Input to begin (unused for authPassword but kept for parity). */
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
 * Password provider - email + authPassword sign-in. Operates against the
 * configured PasswordsFacet so hashing/strength rules live in one
 * place.
 *
 * `begin` is a no-op; authPassword flow has no challenge round-trip.
 * `complete` validates input + rate-limits per email + verifies + emits
 * a `startSession` Intent.
 */
export function authPassword<Profile = unknown>(
  opts: AuthPasswordProvider.IOptions,
): AuthProvider.IProvider<AuthPasswordProvider.IBeginInput, AuthPasswordProvider.ICompleteInput, Profile> {
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
      // email cap per RFC 5321 (254); authPassword cap matches the
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
        throw new AuthError('AUTH_INVALID_CREDENTIALS')
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
        throw new AuthError('AUTH_RATE_LIMITED', {
          retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
        })
      }

      const identity = await opts.findIdentityByEmail(emailCanonical, ctx.tenant.tenantId)
      // ALWAYS run verify (even with no matching identity) to keep timing constant.
      const verifyResult = identity
        ? await opts.passwords.verify(identity.id, pw, ctx.tenant)
        : await opts.passwords.verify(NO_IDENTITY_SENTINEL, pw, ctx.tenant)

      if (!identity || !verifyResult.ok) {
        await ctx.events.emit('signin.failed', { providerId: 'password', reason: 'invalid-credentials' })
        throw new AuthError('AUTH_INVALID_CREDENTIALS')
      }

      if (autoRehash && verifyResult.ok && verifyResult.needsRehash) {
        void opts.passwords.rehash(identity.id, pw, ctx.tenant).catch(() => {})
      }

      return [
        {
          type: 'startSession',
          identityId: identity.id,
          factors: [{ method: 'password', completedAt: new Date() }],
          aal: 1,
        },
      ]
    },
  }
}
