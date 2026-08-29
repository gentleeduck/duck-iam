import type { Anomaly } from '../anomaly/anomaly.types'
import { AuthError } from '../errors'
import type { Identities } from '../identities'
import type { Sessions } from '../sessions'
import { resolveBySid } from '../sessions'
import type { AuthEngine } from './engine'
import type { Engine } from './engine.types'

/**
 * Implementation of {@link AuthEngine.resolveSession}, extracted verbatim.
 * Delegates to the transport's stateless `verify` when available, else looks
 * the session up by hashed sid. Every branch — the cross-tenant guard, the
 * anomaly auto-evaluation — is identical to the inline method it replaced.
 */
export async function resolveSession<Profile extends Identities.ProfileMetadataBase, Tenant, OrgMeta>(
  engine: AuthEngine<Profile, Tenant, OrgMeta>,
  req: { headers: Headers },
  opts: { expectedTenantId?: string; requestSnapshot?: Anomaly.RequestSnapshot } = {},
): Promise<Engine.ResolveResult<Profile> | null> {
  const token = engine.transport.extract(req)
  if (!token) return null

  const finalize = async (
    session: Sessions.Me,
    identity: Identities.Me<Profile> | null,
  ): Promise<Engine.ResolveResult<Profile>> => {
    // Both branches end here, so none can skip it. `resolveBySid` throws too; that copy
    // stays because it is exported and called directly.
    if (session.identityId && !identity) {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'identity-erased' })
    }

    // Auto-evaluate anomaly detectors so routes branch on a single field.
    if (opts.requestSnapshot && identity && engine.anomaly.list().length > 0) {
      try {
        const result = await engine.anomaly.evaluate({ session, identity, req: opts.requestSnapshot })
        return { session, identity, anomaly: result }
      } catch {
        // Detector machinery already catches per-detector throws;
        // this catch defends against a bug in the aggregator itself.
        return { session, identity }
      }
    }
    return { session, identity }
  }

  if (engine.transport.verify) {
    const verified = await engine.transport.verify(token)
    if (verified) {
      // Cross-tenant guard; a token minted under tenant A must not
      // be honoured at a tenant-B endpoint.
      if (opts.expectedTenantId !== undefined && verified.tenantId !== opts.expectedTenantId) {
        return null
      }
      const identity = verified.identityId ? await engine.cfg.stores.identities.findById(verified.identityId) : null
      return finalize(verified, identity)
    }
  }

  const resolved = await resolveBySid(token, engine.cfg.stores.sessions, engine.cfg.stores.identities, {
    ...(opts.expectedTenantId !== undefined && { expectedTenantId: opts.expectedTenantId }),
  })
  if (!resolved) return null
  return finalize(resolved.session, resolved.identity)
}
