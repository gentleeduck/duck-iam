import { assertComplianceStrict, readCompliancePreset, resolveCompliance } from '../compliance'
import type { Compliance } from '../compliance/compliance.types'
import { AuthError } from '../errors'
import type { Identities } from '../identities'
import type { AuthEngine } from './engine'

/** Throws `AUTH_MISCONFIGURED` on any production footgun, and is a no-op outside production. */
export function assertStrict<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(
  engine: AuthEngine<Profile, Tenant, OrgMeta>,
  opts: { env: 'development' | 'production' | 'test'; compliance?: Partial<Compliance.Wired> },
): void {
  // A branded preset is the operator saying what this deployment claims, so it is asserted in every
  // environment. The checks below it are production footguns and stay gated on production, which is
  // also why the preset cannot be folded into them: skipping it outside production would put back
  // the silence this was written to remove.
  assertCompliance(engine, opts.compliance)
  if (opts.env !== 'production') return

  const errors: string[] = []

  if (!hasProductionLimiter(engine)) {
    // Named by cause, and `cfg.limiter` first: the engine falls back to `MemoryLimiter`, so an operator
    // who supplied nothing is holding one too and needs the sentence about supplying one at all.
    errors.push(
      engine.cfg.limiter && Reflect.get(engine.limiter, '__isInProcessLimiter') === true
        ? 'AuthMemoryLimiter rejected in production; its buckets are per node and returned by a restart, so a fleet grants every brute-force budget once per instance'
        : 'Limiter adapter required (brute-force protection); AuthNoopLimiter rejected in production',
    )
  }

  // Over every store, or a mixed deployment runs session state in-process and breaks revocation and
  // rotation across instances. Read off the bag rather than named one by one: `orgs` was the slot the
  // hand-written list was missing, and its only shipped implementation is the memory adapter's.
  for (const [label, store] of Object.entries(engine.cfg.stores)) {
    // By brand, not by constructor name: a name check calls every plain-object store a memory
    // adapter, and each dialect's facets are exactly that, so no SQL deploy could pass strict().
    if (typeof store !== 'object' || store === null) continue
    if (Reflect.get(store, '__isMemoryStore') === true) {
      errors.push(`Memory adapter (${label}) rejected in production; use redis/drizzle/prisma`)
    }
  }

  // An omitted idempotency store falls back to the in-process one, which cannot dedupe across instances.
  // The constructor only refuses when NODE_ENV says production, so this catches the deploy where it is
  // unset -- for the store handed over as well as the one left out, both being the same class.
  if (!engine.cfg.idempotency) {
    errors.push('Idempotency store required; the in-memory fallback cannot dedupe across instances')
  } else if (engine.idempotency.__isInProcessIdempotency) {
    errors.push(
      'AuthMemoryIdempotency rejected in production; its keys are per node, so a retry that lands on another instance replays the operation',
    )
  }

  // A channel that delivers nothing is where a password reset or a magic link goes to die, and the three
  // shipped ones carry the brand for the same NODE_ENV-unset deploy the two checks around this one cover.
  // Over the bag, as the stores are, so a fourth kind is covered the day it is added.
  for (const [kind, channel] of Object.entries(engine.cfg.channels ?? {})) {
    if (typeof channel !== 'object' || channel === null) continue
    if (Reflect.get(channel, '__isNonDeliveringChannel') === true) {
      errors.push(
        `the ${kind} channel ('${String(Reflect.get(channel, 'id') ?? kind)}') delivers nothing and is rejected in production`,
      )
    }
  }

  // Always-pass, so it is the one verifier that cannot fail: every path it fronts is unprotected and says
  // nothing about it. Refused here for the same reason, and on the same NODE_ENV-unset deploy.
  if (Reflect.get(engine.captcha, '__isNullCaptcha') === true) {
    errors.push('AuthNullCaptchaVerifier passes every challenge and is rejected in production')
  }

  // Through the public `secure` getter, never by reaching into private state.
  const maybeSecureGetter = (engine.cfg.transport as { secure?: boolean }).secure
  if (typeof maybeSecureGetter === 'boolean' && maybeSecureGetter === false) {
    errors.push('AuthCookieTransport secure=false rejected in production')
  }

  // A forgeable signature is a forgeable session, so this is checked here rather than at construction,
  // where a short key is merely unwise. Both brands are booleans the holder computed; neither carries
  // the secret. A transport or provider that publishes no brand is not checked, there being no way to
  // read a foreign implementation's key.
  if (Reflect.get(engine.cfg.transport, '__weakSigningKey') === true) {
    errors.push(
      'AuthJwtTransport HS256 signing key is under 32 bytes; RFC 7518 requires a key at least as long as the hash',
    )
  }
  // Through the registry, not `cfg.providers`: a provider passed as a factory is only an instance once
  // it is registered, and `get()` answers the same object either way.
  for (const { id } of engine.providers.list()) {
    if (Reflect.get(engine.providers.get(id), '__weakStateSecret') === true) {
      errors.push(`oauth provider '${id}' has a stateSigningSecret under 32 bytes`)
    }
  }

  // The work factor is the whole of a stored password's strength, and it is a config number like the
  // signing key above: unwise in development, and in production the difference between a stolen table
  // being useless and being a word list. Checked here rather than at construction for exactly that
  // reason. Both shipped hashers publish the verdict against their own defaults; a foreign one publishes
  // nothing and is not judged, there being no way to read another implementation's cost.
  if (
    engine.providers.has('password') &&
    Reflect.get(engine.providers.get('password'), '__weakHasherParams') === true
  ) {
    errors.push(
      'password hasher is configured below its own defaults (scrypt N>=2^14, r>=8, keylen>=32; argon2id memoryCost>=19456, timeCost>=2, hashLength>=32)',
    )
  }

  // HTTPS in production, or oauth callback URLs, magic-link URLs and webhooks go out over plaintext.
  if (typeof engine.cfg.baseUrl === 'string') {
    try {
      const u = new URL(engine.cfg.baseUrl)
      if (u.protocol !== 'https:') {
        errors.push(`baseUrl '${engine.cfg.baseUrl}' must use https:// in production (got ${u.protocol})`)
      }
    } catch {
      errors.push(`baseUrl '${engine.cfg.baseUrl}' is not a valid URL`)
    }
  }

  if ((engine.cfg.providers ?? []).length === 0 && engine.providers.list().length === 0) {
    errors.push('no provider registered; users cannot sign in')
  }

  // Through the public `listenerCount` helper. A bus without it skips the check, there being no way to
  // enforce this against a foreign `Events.IBus`.
  const listenerCount = (engine.events as { listenerCount?: (event: string) => number }).listenerCount
  if (typeof listenerCount === 'function' && listenerCount.call(engine.events, 'lockout') === 0) {
    errors.push('no `lockout` event handler subscribed; operators must wire one (paging, audit, etc.)')
  }

  if (errors.length > 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `production strict() checks failed:\n  - ${errors.join('\n  - ')}`,
    })
  }
}

/** The brand was documented as the hook `strict()` uses to auto-invoke `authAssertComplianceStrict`,
 *  and no caller existed, so branding a config and calling `strict()` ran none of the compliance
 *  assertions and said nothing about having skipped them. */
function assertCompliance<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(engine: AuthEngine<Profile, Tenant, OrgMeta>, supplied: Partial<Compliance.Wired> | undefined): void {
  const preset = readCompliancePreset(engine.cfg)
  if (preset === null) return
  // A minimum AAL of 2 promises every session carries a second factor. Nothing compares a session's
  // aal against it at runtime and nothing at boot could, but a deployment with no mfa provider
  // registered cannot produce an AAL 2 session at all, and that is checkable here.
  // SECURITY: `has`, not `list`. `list` is the sign-in grid and keeps only capabilities exposing
  // begin/complete; `MfaImpl` exposes enroll/verify, so it is registered and never listed. The gate
  // was therefore unsatisfiable, and hipaa and fips - the two presets that raise the floor - refused
  // to boot in every environment, telling the operator no mfa provider was registered while one was.
  if (resolveCompliance(preset).minAal > 1 && !engine.providers.has('mfa')) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'compliance: minAal above 1 requires a registered mfa provider; none is',
    })
  }
  // Evidence last: an operator attests to what the process cannot see, not over what it just observed.
  // The other way round, a deployment could claim `limiterRequired` while holding the Noop limiter.
  assertComplianceStrict({ preset, wired: { ...supplied, ...engineEvidence(engine) } })
}

/**
 * The evidence the engine can see for itself. Everything else is an operator attestation, because
 * nothing in the process can tell whether a BAA was signed or an export path exists.
 */
function engineEvidence<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(engine: AuthEngine<Profile, Tenant, OrgMeta>): Partial<Compliance.Wired> {
  const listenerCount = (engine.events as { listenerCount?: (event: string) => number }).listenerCount
  // Only when a webauthn provider is registered: with none, there is no registration to observe and the
  // key stays absent, which `assertComplianceStrict` already treats as unsatisfied. `mfa`'s webauthn path
  // takes its `attestation` per enrollment call rather than at construction, so nothing at boot can read
  // it and the operator still attests for that one.
  const passkey = engine.providers.list().some((p) => p.id === 'passkey')
    ? {
        webauthnAttestationDirect: Reflect.get(engine.providers.get('passkey'), '__requestsDirectAttestation') === true,
      }
    : {}
  // SECURITY: `fipsValidatedHasher` is the one check in the `fips` preset that the process can see for
  // itself, and it was the one left to an attestation. Measured: a fips deployment running scrypt - or a
  // hasher whose `verify` answers `false` to everything - booted `strict()` clean on the operator typing
  // `true`, while `ARGON2ID_COMPLIANCE`, the exact parameter set the check demands, was exported by the
  // package and read by nothing. Both shipped hashers publish a boolean; a foreign one publishes nothing
  // and the key stays absent, which leaves the attestation standing - the rule `__weakSigningKey` states
  // above, and the case that matters, since FIPS 140 approves no Argon2 at all.
  const fipsHasher = engine.providers.has('password')
    ? Reflect.get(engine.providers.get('password'), '__fipsValidatedHasher')
    : undefined
  return {
    limiterRequired: hasProductionLimiter(engine),
    lockoutListener: typeof listenerCount === 'function' && listenerCount.call(engine.events, 'lockout') > 0,
    ...passkey,
    ...(typeof fipsHasher === 'boolean' && { fipsValidatedHasher: fipsHasher }),
  }
}

/**
 * Whether the engine holds a limiter that can bound anything in production: one the operator supplied,
 * that does not allow everything, and that does not keep its buckets in this process. The engine falls
 * back to `MemoryLimiter`, whose own docstring reads "Dev/test only", so the gate insisting a limiter is
 * wired accepted the one that cannot do the job across a fleet — and the evidence below reported
 * `limiterRequired` satisfied for it, over an operator who attested otherwise.
 *
 * Read by the gate and by the evidence, which are the two places this must mean the same thing.
 */
function hasProductionLimiter(engine: { cfg: { limiter?: unknown }; limiter: object }): boolean {
  if (!engine.cfg.limiter) return false
  return (
    Reflect.get(engine.limiter, '__isNoopLimiter') !== true &&
    Reflect.get(engine.limiter, '__isInProcessLimiter') !== true
  )
}
