import { isCredentialExpired, isRevoked } from '../../credential-utils'
import { AuthError } from '../../errors'
import type { Session } from '../../types/session'
import type { FlowsFacet } from '../flows'

export async function beginSignUp<Profile>(
  deps: FlowsFacet.IDeps<Profile>,
  opts: {
    email: string
    required?: FlowsFacet.ISignUpStage[]
    initialProfile?: Partial<Profile>
    tenantId?: string
  },
): Promise<{ flow: FlowsFacet.ISignUpFlowState<Profile>; flowToken: string }> {
  if (typeof opts.email !== 'string' || opts.email.length === 0 || opts.email.length > 254) {
    throw new AuthError('AUTH_INVALID_CREDENTIALS')
  }
  if (opts.required !== undefined && (!Array.isArray(opts.required) || opts.required.length > 16)) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: 'beginSignUp: required must be an array <=16' })
  }
  const ctx = deps.ctxFactory(opts.tenantId)
  const now = Date.now()
  const required = opts.required ?? ['email-verified', 'terms-accepted']

  const initial = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  const profile: Profile = { ...initial, email: opts.email, emailVerified: false } as Profile

  const created = await ctx.stores.identities.create(
    {
      profile,
      providers: [],
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
    },
    ctx.tenant,
  )

  const flowToken = ctx.crypto.authRandomToken(32)
  const flowTokenHash = ctx.crypto.authSha256(flowToken)
  const dataInit = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  const flow: FlowsFacet.ISignUpFlowState<Profile> = {
    id: ctx.crypto.authRandomToken(8),
    identityId: created.id,
    required,
    completed: ['email-collected'],
    data: { ...dataInit, email: opts.email } as Partial<Profile> & { email: string },
    expiresAt: now + 30 * 60_000,
    absoluteExpiresAt: now + 24 * 60 * 60_000,
    createdAt: now,
  }
  await ctx.stores.credentials.upsert(
    {
      identityId: created.id,
      kind: 'recovery',
      secret: flowTokenHash,
      metadata: { kind: 'signup-flow', flow },
      expiresAt: new Date(flow.absoluteExpiresAt),
    },
    ctx.tenant,
  )
  return { flow, flowToken }
}

export async function getSignUpFlow<Profile>(
  deps: FlowsFacet.IDeps<Profile>,
  flowToken: string,
  tenantId?: string,
): Promise<FlowsFacet.ISignUpFlowState<Profile> | null> {
  const ctx = deps.ctxFactory(tenantId)
  const hash = ctx.crypto.authSha256(flowToken)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row)) return null
  const now = Date.now()
  if (isCredentialExpired(row, now)) {
    await ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    return null
  }
  return parseSignUpFlow<Profile>(row.metadata)
}

export async function advanceSignUp<Profile>(
  deps: FlowsFacet.IDeps<Profile>,
  opts: {
    flowToken: string
    stage: FlowsFacet.ISignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  },
): Promise<FlowsFacet.ISignUpFlowState<Profile>> {
  if (typeof opts.flowToken !== 'string' || opts.flowToken.length === 0 || opts.flowToken.length > 256) {
    throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
  }
  if (typeof opts.stage !== 'string' || opts.stage.length === 0 || opts.stage.length > 64) {
    throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(opts.tenantId)
  const hash = ctx.crypto.authSha256(opts.flowToken)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row)) throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
  const flow = parseSignUpFlow<Profile>(row.metadata)
  if (flow === null) throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')

  const next: FlowsFacet.ISignUpFlowState<Profile> = {
    ...flow,
    completed: flow.completed.includes(opts.stage) ? flow.completed : [...flow.completed, opts.stage],
    data: opts.profilePatch ? { ...flow.data, ...opts.profilePatch } : flow.data,
    expiresAt: Math.min(flow.absoluteExpiresAt, Date.now() + 30 * 60_000),
  }
  try {
    await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
    }
    throw err
  }
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)
  await ctx.stores.credentials.upsert(
    {
      identityId: flow.identityId,
      kind: 'recovery',
      secret: hash,
      metadata: { kind: 'signup-flow', flow: next },
      expiresAt: new Date(flow.absoluteExpiresAt),
    },
    ctx.tenant,
  )
  return next
}

export async function completeSignUp<Profile>(
  deps: FlowsFacet.IDeps<Profile>,
  opts: {
    flowToken: string
    aal?: Session.AAL
    factors?: Session.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    previousSid?: string
  },
): Promise<FlowsFacet.ISignInOutcome> {
  if (typeof opts.flowToken !== 'string' || opts.flowToken.length === 0 || opts.flowToken.length > 256) {
    throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(opts.tenantId)
  const hash = ctx.crypto.authSha256(opts.flowToken)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row)) throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
  const flow = parseSignUpFlow<Profile>(row.metadata)
  if (flow === null) throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')

  const missing = flow.required.filter((stage) => !flow.completed.includes(stage))
  if (missing.length > 0) {
    throw new AuthError('AUTH_SIGNUP_INCOMPLETE', { missing })
  }

  const identity = await ctx.stores.identities.findById(flow.identityId, ctx.tenant)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
  const baseProfile = isPlainObject(identity.profile) ? identity.profile : {}
  const mergedProfile: Profile = { ...baseProfile, ...flow.data } as Profile
  await ctx.stores.identities.update(identity.id, { profile: mergedProfile }, identity.version, ctx.tenant)
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)

  const factors = opts.factors ?? [{ method: 'magic-link', completedAt: new Date() }]
  const aal = opts.aal ?? 1
  const { session, sid, csrfToken } = await deps.sessions.rotateOrCreate({
    purpose: 'guest-promotion',
    ...(opts.previousSid !== undefined && { previousSid: opts.previousSid }),
    identityId: flow.identityId,
    kind: 'user',
    aal,
    factors,
    ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
    ...(opts.ip !== undefined && { ip: opts.ip }),
    ...(opts.userAgent !== undefined && { userAgent: opts.userAgent }),
  })
  const intents = deps.transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
  return { session, sid, intents }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const SIGNUP_STAGE_VALUES: ReadonlySet<string> = new Set([
  'email-collected',
  'email-verified',
  'profile-completed',
  'mfa-enrolled',
  'terms-accepted',
  'completed',
])

function isSignUpStage(v: string): v is FlowsFacet.ISignUpStage {
  return SIGNUP_STAGE_VALUES.has(v)
}

function parseSignUpFlow<Profile>(meta: unknown): FlowsFacet.ISignUpFlowState<Profile> | null {
  if (!isPlainObject(meta)) return null
  if (meta.kind !== 'signup-flow') return null
  const flow = meta.flow
  if (!isPlainObject(flow)) return null
  if (typeof flow.id !== 'string' || flow.id.length === 0) return null
  if (typeof flow.identityId !== 'string' || flow.identityId.length === 0) return null
  if (!Array.isArray(flow.required)) return null
  if (!Array.isArray(flow.completed)) return null
  if (typeof flow.expiresAt !== 'number' || !Number.isFinite(flow.expiresAt)) return null
  if (typeof flow.absoluteExpiresAt !== 'number' || !Number.isFinite(flow.absoluteExpiresAt)) return null
  if (typeof flow.createdAt !== 'number' || !Number.isFinite(flow.createdAt)) return null
  const required: FlowsFacet.ISignUpStage[] = []
  for (const s of flow.required) {
    if (typeof s !== 'string' || !isSignUpStage(s)) return null
    required.push(s)
  }
  const completed: FlowsFacet.ISignUpStage[] = []
  for (const s of flow.completed) {
    if (typeof s === 'string' && isSignUpStage(s)) completed.push(s)
  }
  const data = isPlainObject(flow.data) ? flow.data : {}
  return {
    id: flow.id,
    identityId: flow.identityId,
    required,
    completed,
    data: data as Partial<Profile> & { email: string },
    expiresAt: flow.expiresAt,
    absoluteExpiresAt: flow.absoluteExpiresAt,
    createdAt: flow.createdAt,
  }
}
