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
  // SECURITY: `realSid` is documented as the real subject's, and an impersonating session's subject is the
  // target. Nesting took `actingAs.realIdentityId` from `real.identityId`, so hop two named the previous
  // target as the accountable human and `releaseImpersonation` then handed out a session as them with
  // `actingAs: null` and the full session lifetime - a sixty-minute audited impersonation laundered into an
  // unmarked week-long one, with `identity.impersonated` recording the wrong operator on the way through.
  if (real.actingAs) {
    throw new AuthError('AUTH_IMPERSONATE_FORBIDDEN', { reason: 'cannot impersonate from an impersonated session' })
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
    // The row's own deadlines, not just the marker's, so the row dies with the window.
    ttlMs,
    actingAs: {
      realIdentityId: real.identityId,
      startedAt: nowDate,
      reason: opts.reason,
      expiresAt: new Date(now + ttlMs),
    },
  })
  await deps.events.emit('identity.impersonated', {
    // Set here: this emits outside any request scope, so the automatic stamper has nothing to read.
    audit: { actorId: real.identityId },
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
): Promise<{ session: Sessions.Me | null; sid: string | null; intents: Provider.Intent[] }> {
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
    // `null`, not `''`: a type promising a string invites the `session` check to be skipped.
    return { intents: deps.transport.revoke(), session: null, sid: null }
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
  await deps.events.emit('identity.impersonation.ended', {
    audit: { actorId: realIdentityId },
    endedBy: 'release',
    realIdentityId,
    sessionId: session.id,
    targetIdentityId: session.identityId,
  })
  const intents = deps.transport.issue(sid, restored, { fresh: true, absolute: false, csrfToken })
  return { session: restored, sid, intents }
}
