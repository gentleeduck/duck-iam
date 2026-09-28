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
        : 'Limiter adapter required (brute-force protection); NoopLimiter rejected in production',
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
      errors.push(`Memory adapter (${label}) rejected in production; use the drizzle, redis or valkey adapter`)
    }
  }

  // Read off `cfg.events`, not `engine.events`: `withAuditStamping` wraps the bus in a fresh object
  // literal that carries no brand. An omitted bus is the engine's own `InMemoryEvents` fallback, so both
  // spellings of the same mistake are named.
  if (!engine.cfg.events) {
    errors.push('Event bus required; the in-process fallback drops every event raised on another instance')
  } else if (Reflect.get(engine.cfg.events, '__isInProcessBus') === true) {
    errors.push(
      'AuthInMemoryEvents rejected in production; its handlers are per node, so a lockout, a revocation or a `suspicious` signal raised on one instance is never heard by the others - the `lockout` check below included',
    )
  }

  // Always-pass, so it is the one verifier that cannot fail: every path it fronts is unprotected and says
  // nothing about it. Refused here for the same reason, and on the same NODE_ENV-unset deploy.
  if (Reflect.get(engine.captcha, '__isNullCaptcha') === true) {
    errors.push('AuthNullCaptchaVerifier passes every challenge and is rejected in production')
  }

  // `allowInsecureEndpoint` cannot reach loopback - the SSRF guard refuses that whatever the flag says -
  // so the only thing it permits is cleartext to a public host, and anyone on that path reads the secret
  // and can mint solves with it from then on.
  if (Reflect.get(engine.captcha, '__insecureCaptchaEndpoint') === true) {
    errors.push('captcha siteverify endpoint is plaintext http, so the provider secret is posted in the clear')
  }

  // A composite's parts, nested ones too, are checked as if each were configured alone.
  const transports: object[] = [engine.cfg.transport]
  for (const t of transports) {
    const parts = Reflect.get(t, 'transports')
    if (Array.isArray(parts)) transports.push(...parts)
  }

  // Through the public `secure` getter, never by reaching into private state.
  if (transports.some((t) => Reflect.get(t, 'secure') === false)) {
    errors.push('AuthCookieTransport secure=false rejected in production')
  }

  // A forgeable signature is a forgeable session, so this is checked here rather than at construction,
  // where a short key is merely unwise. Both brands are booleans the holder computed; neither carries
  // the secret. A transport or provider that publishes no brand is not checked, there being no way to
  // read a foreign implementation's key.
  if (transports.some((t) => Reflect.get(t, '__weakSigningKey') === true)) {
    errors.push(
      'JwtTransport HS256 signing key is under 32 bytes; RFC 7518 requires a key at least as long as the hash',
    )
  }
  // Through the registry, not `cfg.providers`: a provider passed as a factory is only an instance once
  // it is registered, and `get()` answers the same object either way.
  for (const { id } of engine.providers.list()) {
    if (Reflect.get(engine.providers.get(id), '__weakStateSecret') === true) {
      errors.push(`oauth provider '${id}' has a stateSigningSecret under 32 bytes`)
    }
    // Development is where `allowStateReplay` earns its keep, production is where a state that nothing
    // burns is a callback URL that keeps working for ten minutes.
    if (Reflect.get(engine.providers.get(id), '__stateReplayAllowed') === true) {
      errors.push(
        `oauth provider '${id}' was built with \`allowStateReplay: true\`, rejected in production; pass \`nonceStore: redisDPoPNonceStore({ redis, prefix: 'auth:oauth:nonce' })\``,
      )
    }
    // The challenge is the whole of a WebAuthn ceremony's binding, and `take` consuming it in one
    // process leaves it live in every other: the assertion a pod just spent replays on its neighbours
    // for the rest of the TTL.
    if (Reflect.get(engine.providers.get(id), '__inProcessChallengeStore') === true) {
      errors.push(
        `provider '${id}' holds AuthMemoryPasskeyChallengeStore, rejected in production; pass \`challengeStore: redisPasskeyChallengeStore({ redis })\``,
      )
    }
    // Boot, not first request: the provider refuses every link request, and only once a user has asked.
    // Its own `deliver`, not `cfg.deliver`, which reaches it only when a thunk passes it on.
    if (Reflect.get(engine.providers.get(id), '__noDeliver') === true) {
      errors.push(`provider '${id}' has no \`deliver\`, so no link can ever be sent`)
    }
  }

  // The work factor is a stored password's whole strength. Both shipped hashers publish a verdict against
  // their own defaults; a foreign hasher publishes none and is not judged.
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

  // Counted in the registry: `providers` drops a falsy entry and a thunk that answers nothing.
  if (engine.providers.size === 0) {
    errors.push('no provider registered; users cannot sign in')
  }

  // A bus without `listenerCount` skips the check, there being no way to enforce this against it.
  if (engine.events.listenerCount?.('lockout') === 0) {
    errors.push('no `lockout` event handler subscribed; operators must wire one (paging, audit, etc.)')
  }

  if (errors.length > 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `production strict() checks failed:\n  - ${errors.join('\n  - ')}`,
    })
  }
}

/** Runs `assertComplianceStrict` for the preset the config is branded with, so branding it and calling
 *  `strict()` is one step rather than two. */
function assertCompliance<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(engine: AuthEngine<Profile, Tenant, OrgMeta>, supplied: Partial<Compliance.Wired> | undefined): void {
  const preset = readCompliancePreset(engine.cfg)
  if (preset === null) return
  // A deployment with no mfa provider cannot produce an AAL 2 session.
  // SECURITY: `has`, not `list`: `list` keeps only sign-in capabilities, and `MfaImpl` is never in it.
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
  // Only when a webauthn provider is registered: with none, there is no registration to observe and the
  // key stays absent, which `assertComplianceStrict` already treats as unsatisfied. `mfa`'s webauthn path
  // takes its `attestation` per enrollment call rather than at construction, so nothing at boot can read
  // it and the operator still attests for that one.
  const passkey = engine.providers.list().some((p) => p.id === 'passkey')
    ? {
        webauthnAttestationDirect: Reflect.get(engine.providers.get('passkey'), '__requestsDirectAttestation') === true,
      }
    : {}
  // SECURITY: `fipsValidatedHasher` is the one check in the `fips` preset the process can see for itself,
  // and it was left to the operator's attestation. Both shipped hashers publish a boolean; a foreign one
  // publishes nothing, the key stays absent and the attestation stands, as `__weakSigningKey` has it.
  const fipsHasher = engine.providers.has('password')
    ? Reflect.get(engine.providers.get('password'), '__fipsValidatedHasher')
    : undefined
  return {
    limiterRequired: hasProductionLimiter(engine),
    lockoutListener: (engine.events.listenerCount?.('lockout') ?? 0) > 0,
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
