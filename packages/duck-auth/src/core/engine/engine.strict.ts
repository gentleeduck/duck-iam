import { AuthError } from '../errors'
import type { Identity } from '../identities'
import type { AuthEngine } from './engine'

/**
 * Boot-time strict validation extracted from {@link AuthEngine.strict}. Throws
 * `AUTH_MISCONFIGURED` on any production footgun; a no-op outside production.
 * Every validation and thrown error is identical to the inline method it replaced.
 */
export function assertStrict<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(engine: AuthEngine<Profile, Tenant, OrgMeta>, opts: { env: 'development' | 'production' | 'test' }): void {
  if (opts.env !== 'production') return

  const errors: string[] = []

  // Reject AuthNoopLimiter via class brand (bundlers rename constructors).
  if (!engine.config.limiter || (engine.limiter as { __isNoopLimiter?: boolean }).__isNoopLimiter === true) {
    errors.push('Limiter adapter required (brute-force protection); AuthNoopLimiter rejected in production')
  }

  // Memory adapter detection over every store; mixed deployments would otherwise
  // run session state in-process and break revocation/rotation across instances.
  const stores: Array<{ obj: unknown; label: string }> = [
    { obj: engine.config.stores.identities, label: 'identities' },
    { obj: engine.config.stores.sessions, label: 'sessions' },
    { obj: engine.config.stores.credentials, label: 'credentials' },
  ]
  for (const { obj, label } of stores) {
    const name = (obj as { constructor?: { name?: string } }).constructor?.name ?? ''
    if (name === 'Object' || /Memory/i.test(name)) {
      errors.push(`Memory adapter (${label}) rejected in production; use redis/drizzle/prisma`)
    }
  }

  // Transport secure-cookie check via the public `secure` getter so
  // we never reach into private state.
  const maybeSecureGetter = (engine.config.transport as { secure?: boolean }).secure
  if (typeof maybeSecureGetter === 'boolean' && maybeSecureGetter === false) {
    errors.push('AuthCookieTransport secure=false rejected in production')
  }

  // baseUrl must use HTTPS in production so oauth callback URLs, magic-link
  // URLs, and webhooks aren't issued over plaintext.
  if (typeof engine.config.baseUrl === 'string') {
    try {
      const u = new URL(engine.config.baseUrl)
      if (u.protocol !== 'https:') {
        errors.push(`baseUrl '${engine.config.baseUrl}' must use https:// in production (got ${u.protocol})`)
      }
    } catch {
      errors.push(`baseUrl '${engine.config.baseUrl}' is not a valid URL`)
    }
  }

  if ((engine.config.providers ?? []).length === 0 && engine.providers.list().length === 0) {
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
