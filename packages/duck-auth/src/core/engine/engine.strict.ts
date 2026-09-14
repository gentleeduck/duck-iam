import { assertComplianceStrict, readCompliancePreset, resolveCompliance } from '../compliance'
import type { Compliance } from '../compliance/compliance.types'
import { AuthError } from '../errors'
import type { Identities } from '../identities'
import type { AuthEngine } from './engine'

/**
 * Boot-time strict validation extracted from {@link AuthEngine.strict}. Throws
 * `AUTH_MISCONFIGURED` on any production footgun; a no-op outside production.
 * Every validation and thrown error is identical to the inline method it replaced.
 */
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

  // Reject AuthNoopLimiter via class brand (bundlers rename constructors).
  if (!engine.cfg.limiter || (engine.limiter as { __isNoopLimiter?: boolean }).__isNoopLimiter === true) {
    errors.push('Limiter adapter required (brute-force protection); AuthNoopLimiter rejected in production')
  }

  // Memory adapter detection over every store; mixed deployments would otherwise
  // run session state in-process and break revocation/rotation across instances.
  const stores: Array<{ obj: object; label: string }> = [
    { obj: engine.cfg.stores.identities, label: 'identities' },
    { obj: engine.cfg.stores.sessions, label: 'sessions' },
    { obj: engine.cfg.stores.credentials, label: 'credentials' },
  ]
  for (const { obj, label } of stores) {
    // By brand, not by constructor name: a name check calls every plain-object store a memory
    // adapter, and each dialect's facets are exactly that, so no SQL deploy could pass strict().
    if (Reflect.get(obj, '__isMemoryStore') === true) {
      errors.push(`Memory adapter (${label}) rejected in production; use redis/drizzle/prisma`)
    }
  }

  // An omitted idempotency store falls back to the in-process one, which cannot
  // dedupe across instances. The constructor only refuses when NODE_ENV says
  // production; this catches the deploy where it is unset.
  if (!engine.cfg.idempotency) {
    errors.push('Idempotency store required; the in-memory fallback cannot dedupe across instances')
  }

  // Transport secure-cookie check via the public `secure` getter so
  // we never reach into private state.
  const maybeSecureGetter = (engine.cfg.transport as { secure?: boolean }).secure
  if (typeof maybeSecureGetter === 'boolean' && maybeSecureGetter === false) {
    errors.push('AuthCookieTransport secure=false rejected in production')
  }

  // baseUrl must use HTTPS in production so oauth callback URLs, magic-link
  // URLs, and webhooks aren't issued over plaintext.
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

  // `lockout` listener via the public `listenerCount` introspection
  // helper. Bus implementations without the helper skip this check
  // (we cannot enforce against a foreign Events.IBus impl).
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

/**
 * The brand was documented as the hook `strict()` uses to "auto-invoke authAssertComplianceStrict
 * so operators do not have to remember the second call", and no caller existed - so branding a
 * config and calling `strict()` ran none of the compliance assertions and said nothing about having
 * skipped them.
 */
function assertCompliance<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(engine: AuthEngine<Profile, Tenant, OrgMeta>, supplied: Partial<Compliance.Wired> | undefined): void {
  const preset = readCompliancePreset(engine.cfg)
  if (preset === null) return
  // A minimum AAL of 2 is a promise that every session carries a second factor. Nothing compares a
  // session's aal against it at runtime, and nothing at boot can - but a deployment with no mfa
  // provider registered cannot produce an AAL 2 session at all, which is checkable here.
  if (resolveCompliance(preset).minAal > 1 && !engine.providers.list().some((p) => p.id === 'mfa')) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'compliance: minAal above 1 requires a registered mfa provider; none is',
    })
  }
  assertComplianceStrict({ preset, wired: { ...engineEvidence(engine), ...supplied } })
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
  return {
    limiterRequired:
      Boolean(engine.cfg.limiter) && (engine.limiter as { __isNoopLimiter?: boolean }).__isNoopLimiter !== true,
    lockoutListener: typeof listenerCount === 'function' && listenerCount.call(engine.events, 'lockout') > 0,
  }
}
