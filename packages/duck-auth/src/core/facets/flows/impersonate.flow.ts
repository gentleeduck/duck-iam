import { AuthError } from '~/core/errors'
import type { Identity } from '~/core/types'
import type { Provider } from '~/core/types/provider'
import type { Session } from '~/core/types/session'
import type { FlowsFacet } from '../flows.facet'

export async function impersonate<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  opts: FlowsFacet.ImpersonateOptions & {
    authorize: (realSession: Session.Me, targetIdentityId: string) => Promise<boolean>
  },
): Promise<FlowsFacet.ImpersonateOutcome> {
  if (
    typeof opts.targetIdentityId !== 'string' ||
    opts.targetIdentityId.length === 0 ||
    opts.targetIdentityId.length > 256
  ) {
    throw new AuthError('AUTH_IMPERSONATE_FORBIDDEN', { reason: 'invalid target' })
  }
  if (typeof opts.reason !== 'string' || opts.reason.length === 0 || opts.reason.length > 256) {
    throw new AuthError('AUTH_IMPERSONATE_FORBIDDEN', { reason: 'reason must be 1-256 chars' })
  }
  const real = await deps.sessions.getBySid(opts.realSid)
  if (!real?.identityId) {
    throw new AuthError('AUTH_UNAUTHENTICATED')
  }
  if (real.identityId === opts.targetIdentityId) {
    throw new AuthError('AUTH_IMPERSONATE_FORBIDDEN', { reason: 'cannot impersonate self' })
  }
  const allowed = await opts.authorize(real, opts.targetIdentityId)
  if (!allowed) {
    throw new AuthError('AUTH_IMPERSONATE_FORBIDDEN', { reason: 'authorize() returned false' })
  }

  const ttlMs = Math.min(opts.ttlMs ?? 60 * 60_000, 60 * 60_000)
  const now = Date.now()
  const nowDate = new Date(now)
  const target = await deps.identities.getById(
    opts.targetIdentityId,
    opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
  )
  if (!target) throw new AuthError('AUTH_UNAUTHENTICATED')

  const { session, sid, csrfToken } = await deps.sessions.rotateOrCreate({
    purpose: 'impersonate-start',
    previousSid: opts.realSid,
    identityId: opts.targetIdentityId,
    kind: 'user',
    aal: real.aal,
    factors: real.factors,
    ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
    actingAs: {
      realIdentityId: real.identityId,
      startedAt: nowDate,
      reason: opts.reason,
      expiresAt: new Date(now + ttlMs),
    },
  })
  await deps.events.emit('identity.impersonated', {
    realIdentityId: real.identityId,
    targetIdentityId: opts.targetIdentityId,
    reason: opts.reason,
  })
  const intents = deps.transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
  return { session, sid, intents }
}

export async function releaseImpersonation<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  impersonationSid: string,
): Promise<{ intents: Provider.Intent[] }> {
  const session = await deps.sessions.getBySid(impersonationSid)
  if (!session?.actingAs) {
    throw new AuthError('AUTH_IMPERSONATE_EXPIRED')
  }
  await deps.sessions.revoke(impersonationSid)
  return { intents: deps.transport.revoke() }
}
