import type { Identity } from '../../core'
import { AuthError } from '../../core/errors'
import type { Provider } from '../../core/types/provider'
import { ScryptHasher } from './hashers/scrypt.hasher'
import { toPasswordsConfig } from './password.config'
import { NO_IDENTITY_SENTINEL } from './password.constants'
import { PasswordsFacet } from './password.facet'
import type { Password } from './password.types'

/**
 * Password provider - email + authPassword sign-in. Operates against the
 * configured PasswordsFacet so hashing/strength rules live in one
 * place.
 *
 * `begin` is a no-op; authPassword flow has no challenge round-trip.
 * `complete` validates input + rate-limits per email + verifies + emits
 * a `startSession` Intent.
 */
export function password<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: Password.Options,
): Provider.Me<Password.BeginInput, Password.CompleteInput, Profile> {
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

/**
 * Password capability module (mechanism A). Owns the PasswordsFacet + its
 * config and mounts it onto the engine at construction, exposing `auth.passwords`.
 * Add it to `providers: [passwordProvider()]`.
 *
 * The email+password *sign-in* provider ({@link password}) is registered
 * separately by the app, since it needs an app-specific `findIdentityByEmail`.
 */
export function passwordProvider<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: Password.ConfigInput): Provider.ProviderModule<Profile, Tenant, OrgMeta> {
  return {
    name: 'password',
    attach(engine) {
      engine.setPasswords(
        new PasswordsFacet(engine.config.stores.credentials, cfg?.hasher ?? new ScryptHasher(), toPasswordsConfig(cfg)),
      )
    },
  }
}
