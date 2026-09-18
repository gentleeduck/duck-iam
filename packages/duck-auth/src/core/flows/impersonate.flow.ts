import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { Flows } from './flows.types'

export async function impersonate<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.ImpersonateOptions & {
    authorize: (realSession: Sessions.Me, targetIdentityId: string) => Promise<boolean>
  },
): Promise<Flows.ImpersonateOutcome> {
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
  if (
    opts.iamDecisionId !== undefined &&
    (typeof opts.iamDecisionId !== 'string' || opts.iamDecisionId.length === 0 || opts.iamDecisionId.length > 256)
  ) {
    throw new AuthError('AUTH_IMPERSONATE_FORBIDDEN', { reason: 'iamDecisionId must be 1-256 chars' })
  }
  const real = await deps.sessions.getBySid(opts.realSid).orNull()
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
  const target = await deps.identities.getById(opts.targetIdentityId).orNull()
  if (!target) throw new AuthError('AUTH_UNAUTHENTICATED')

  const { session, sid, csrfToken } = await deps.sessions.rotateOrCreate({
    purpose: 'impersonate-start',
    previousSid: opts.realSid,
    identityId: opts.targetIdentityId,
    // Subject is the target; `actingAs` below records the real admin.
    identity: target,
    kind: 'user',
    // AAL 1 and no factors, never the admin's. `aal` and `factors` describe what the session's
    // *subject* did to prove they are there, and the subject of this row is the target, who did
    // nothing.
    aal: 1,
    factors: [],
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
    ...(opts.iamDecisionId !== undefined && { iamDecisionId: opts.iamDecisionId }),
  })
  const intents = deps.transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
  return { session, sid, intents }
}

/** End an impersonation and hand the operator back a session of their own. */
export async function releaseImpersonation<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  impersonationSid: string,
): Promise<{ session: Sessions.Me | null; sid: string; intents: Provider.Intent[] }> {
  const session = await deps.sessions.getBySid(impersonationSid).orNull()
  if (!session?.actingAs) {
    throw new AuthError('AUTH_IMPERSONATE_EXPIRED')
  }
  const realIdentityId = session.actingAs.realIdentityId
  const real = await deps.identities.getById(realIdentityId).orNull()
  if (!real) {
    // The operator's own account went away while they were impersonating: deleted, erased or merged.
    // There is no session to return them to, so the impersonation ends revoked with the bearer cleared.
    await deps.sessions.revoke(impersonationSid).orNull()
    return { intents: deps.transport.revoke(), session: null, sid: '' }
  }
  const {
    session: restored,
    sid,
    csrfToken,
  } = await deps.sessions.rotateOrCreate({
    purpose: 'impersonate-release',
    previousSid: impersonationSid,
    identityId: realIdentityId,
    identity: real,
    kind: 'user',
    aal: 1,
    factors: [],
    ...(session.tenantId !== null && { tenantId: session.tenantId }),
  })
  const intents = deps.transport.issue(sid, restored, { fresh: true, absolute: false, csrfToken })
  return { session: restored, sid, intents }
}
