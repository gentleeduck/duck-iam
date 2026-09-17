import { ABSENT, orNull } from '~/core/answer'
import type { Anomaly } from '../anomaly/anomaly.types'
import { AuthError, asAuthError } from '../errors'
import type { Identities } from '../identities'
import type { Sessions } from '../sessions'
import { resolveBySid } from '../sessions'
import { DEFAULT_SESSION_CONFIG } from '../sessions/sessions.constants'
import type { AuthEngine } from './engine'
import type { Engine } from './engine.types'

/**
 * Delegates to the transport's stateless `verify` where there is one, and otherwise looks the session up by
 * hashed sid. Rejects `AUTH_SESSION_REVOKED` where the request carries nobody, which is in the absent set,
 * so the engine method's `orNull()` reads it back as null.
 */
export async function resolveSession<Profile extends Identities.ProfileMetadataBase, Tenant, OrgMeta>(
  engine: AuthEngine<Profile, Tenant, OrgMeta>,
  req: { headers: Headers },
  opts: { expectedTenantId?: string; requestSnapshot?: Anomaly.RequestSnapshot } = {},
): Promise<Engine.ResolveResult<Profile>> {
  const token = engine.transport.extract(req)
  if (!token) throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the request carries no transport token' })

  const finalize = async (
    session: Sessions.Me,
    identity: Identities.Me<Profile> | null,
  ): Promise<Engine.ResolveResult<Profile>> => {
    // Both branches end here, so none can skip it. `resolveBySid` throws too; that copy
    // stays because it is exported and called directly.
    if (session.identityId && !identity) {
      throw new AuthError('AUTH_SESSION_IDENTITY_ERASED')
    }

    // The detectors run here, so a route branches on one field.
    if (opts.requestSnapshot && identity && engine.anomaly.list().length > 0) {
      try {
        const result = await engine.anomaly.evaluate({ session, identity, req: opts.requestSnapshot })
        return { session, identity, anomaly: result }
      } catch {
        // The detector machinery catches a per-detector throw; this catches a bug in the aggregator.
        return { session, identity }
      }
    }
    return { session, identity }
  }

  // SECURITY: `AUTH_SESSION_EXPIRED` is the one refusal a transport reaches only about a token it
  // authenticated -- every "not a token of mine" rejection is `AUTH_SESSION_REVOKED` -- so it is kept and
  // answered below. The store cannot improve on it: it is keyed by sid hash and holds no row for a minted
  // token, so falling through would replace a dated verdict with "no session for that sid".
  let expiredByTransport: unknown
  if (engine.transport.verify) {
    // A transport whose dependency broke still throws here rather than being read as "not signed in";
    // every other refusal falls through to the store lookup below, as `orNull` did.
    const verified = await engine.transport.verify(token).catch((err: unknown) => {
      const { code } = asAuthError(err, 'AUTH_ADAPTER_FAILED')
      if (!ABSENT.has(code)) throw err
      if (code === 'AUTH_SESSION_EXPIRED') expiredByTransport = err
      return null
    })
    if (verified) {
      // A token minted under tenant A must not be honoured at a tenant-B endpoint.
      if (opts.expectedTenantId !== undefined && verified.tenantId !== opts.expectedTenantId) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the token was minted for another tenant' })
      }
      const identity = verified.identityId
        ? await orNull(engine.cfg.stores.identities.find({ id: verified.identityId }))
        : null
      return finalize(verified, identity)
    }
  }

  const resolved = await resolveBySid(token, engine.cfg.stores.sessions, engine.cfg.stores.identities, {
    // The engine's own window, so `session.fresh` means the same thing here as it
    // does on the JWT path, which has always recomputed it from `rotatedAt`.
    freshnessMs: engine.cfg.session?.freshnessMs ?? DEFAULT_SESSION_CONFIG.freshnessMs,
    ...(opts.expectedTenantId !== undefined && { expectedTenantId: opts.expectedTenantId }),
  }).catch((err: unknown) => {
    throw expiredByTransport ?? err
  })

  return finalize(resolved.session, resolved.identity)
}
