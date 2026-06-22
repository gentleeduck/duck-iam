import { AuthErrorObject } from '../../errors'
import type { AuthProvider } from '../../types/provider'
import type { AuthSession } from '../../types/session'
import type { FlowsFacet } from '../flows'

export async function impersonate<Profile>(
  flows: FlowsFacet<Profile>,
  opts: FlowsFacet.IImpersonateOptions & {
    authorize: (realSession: AuthSession.ISession, targetIdentityId: string) => Promise<boolean>
  },
): Promise<FlowsFacet.IImpersonateOutcome> {
  if (
    typeof opts.targetIdentityId !== 'string' ||
    opts.targetIdentityId.length === 0 ||
    opts.targetIdentityId.length > 256
  ) {
    throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'invalid target' })
  }
  if (typeof opts.reason !== 'string' || opts.reason.length === 0 || opts.reason.length > 256) {
    throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'reason must be 1-256 chars' })
  }
  const real = await flows._sessions.getBySid(opts.realSid)
  if (!real?.identityId) {
    throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
  }
  if (real.identityId === opts.targetIdentityId) {
    throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'cannot impersonate self' })
  }
  const allowed = await opts.authorize(real, opts.targetIdentityId)
  if (!allowed) {
    throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'authorize() returned false' })
  }

  const ttlMs = Math.min(opts.ttlMs ?? 60 * 60_000, 60 * 60_000)
  const now = Date.now()
  const target = await flows._identities.getById(
    opts.targetIdentityId,
    opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
  )
  if (!target) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

  const { session, sid, csrfToken } = await flows._sessions.rotateOrCreate({
    purpose: 'impersonate-start',
    previousSid: opts.realSid,
    identityId: opts.targetIdentityId,
    kind: 'user',
    aal: real.aal,
    factors: real.factors,
    ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
    actingAs: {
      realIdentityId: real.identityId,
      startedAt: now,
      reason: opts.reason,
      expiresAt: now + ttlMs,
    },
  })
  await flows._events.emit('identity.impersonated', {
    realIdentityId: real.identityId,
    targetIdentityId: opts.targetIdentityId,
    reason: opts.reason,
  })
  const intents = flows._transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
  return { session, sid, intents }
}

export async function releaseImpersonation<Profile>(
  flows: FlowsFacet<Profile>,
  impersonationSid: string,
): Promise<{ intents: AuthProvider.Intent[] }> {
  const session = await flows._sessions.getBySid(impersonationSid)
  if (!session?.actingAs) {
    throw new AuthErrorObject('AUTH/IMPERSONATE_EXPIRED')
  }
  await flows._sessions.revoke(impersonationSid)
  return { intents: flows._transport.revoke() }
}
