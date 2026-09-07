import { isCredentialExpired, isRevoked, toCredentialUpsert } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { Flows } from './flows.types'

export async function beginSignUp<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: {
    email: string
    required?: Flows.SignUpStage[]
    initialProfile?: Partial<Profile>
    tenantId?: string
  },
): Promise<{ flow: Flows.SignUpFlowState<Profile>; flowToken: string }> {
  if (typeof opts.email !== 'string' || opts.email.length === 0 || opts.email.length > 254) {
    throw new AuthError('AUTH_INVALID_CREDENTIALS')
  }
  if (opts.required !== undefined && (!Array.isArray(opts.required) || opts.required.length > 16)) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: 'beginSignUp: required must be an array <=16' })
  }
  const ctx = deps.ctxFactory(opts.tenantId)
  const now = Date.now()
  const required = opts.required ?? ['email-verified', 'terms-accepted']

  // The only flow in the unit that never consumed the limiter - password reset,
  // email verification and account deletion all do. Without it one unauthenticated
  // request equals one permanent identity row, unbounded. Keyed on the address, the
  // same shape `requestPasswordReset` uses, so hammering one victim's address is
  // what gets capped.
  const emailCanonical = opts.email.trim().toLowerCase()
  const limited = await ctx.limiter.consume(`signup:begin:${emailCanonical}`)
  if (!limited.ok) {
    throw new AuthError('AUTH_RATE_LIMITED', {
      retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
    })
  }

  const initial = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  // No cast. `ProfileMetadataBase` requires `username`, duck-auth's own Postgres
  // schema enforces it with a CHECK and a unique index, and this line used to
  // launder a profile without one past the type with `as unknown as Profile` -
  // so `beginSignUp({ email })`, the documented happy path, produced an INSERT
  // that the library's own adapter rejects. Nothing caught it because the sqlite
  // conformance DDL omits CHECK constraints and memory/Redis have no schema.
  const profile = buildSignUpProfile<Profile>(initial, opts.email)

  const created = await ctx.stores.identities.create({
    profile,
    providers: [],
    emailVerified: false,
  })

  const flowToken = ctx.crypto.authRandomToken(32)
  const flowTokenHash = ctx.crypto.authSha256(flowToken)
  const dataInit = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  const flow: Flows.SignUpFlowState<Profile> = {
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
    toCredentialUpsert({
      identityId: created.id,
      kind: 'recovery',
      secret: flowTokenHash,
      metadata: { flow, purpose: 'signup-flow' },
      expiresAt: new Date(flow.absoluteExpiresAt),
    }),
    ctx.tenant,
  )
  return { flow, flowToken }
}

export async function getSignUpFlow<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  flowToken: string,
  tenantId?: string,
): Promise<Flows.SignUpFlowState<Profile> | null> {
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

export async function advanceSignUp<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: {
    flowToken: string
    stage: Flows.SignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  },
): Promise<Flows.SignUpFlowState<Profile>> {
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

  const next: Flows.SignUpFlowState<Profile> = {
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
    toCredentialUpsert({
      identityId: flow.identityId,
      kind: 'recovery',
      secret: hash,
      metadata: { flow: next, purpose: 'signup-flow' },
      expiresAt: new Date(flow.absoluteExpiresAt),
    }),
    ctx.tenant,
  )
  return next
}

export async function completeSignUp<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: {
    flowToken: string
    aal?: Sessions.AAL
    factors?: Sessions.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    previousSid?: string
  },
): Promise<Flows.SignInOutcome> {
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

  const identity = await ctx.stores.identities.findById(flow.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
  const baseProfile = isPlainObject(identity.profile) ? identity.profile : {}
  const mergedProfile: Profile = { ...baseProfile, ...flow.data } as Profile
  // `identity` is stale past this line; listeners need the profile we just wrote.
  const merged = await ctx.stores.identities.update(identity.id, { profile: mergedProfile }, identity.version)
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)

  const factors = opts.factors ?? [{ method: 'magic-link', completedAt: new Date() }]
  const aal = opts.aal ?? 1
  const { session, sid, csrfToken } = await deps.sessions.rotateOrCreate({
    purpose: 'guest-promotion',
    ...(opts.previousSid !== undefined && { previousSid: opts.previousSid }),
    identityId: flow.identityId,
    identity: merged,
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

/**
 * Total a caller's partial profile into one the identity store will accept.
 *
 * `username` is required by the type and by the Postgres CHECK, and
 * `beginSignUp`'s `initialProfile` is optional, so something has to supply it.
 * Deriving beats requiring it: a signature change would break every caller for
 * a field most signups do not collect until a later stage, and the derived
 * handle is replaced by `completeSignUp` the moment the flow carries a real one.
 *
 * The address itself, not its local part. `username` carries a unique index of
 * its own, so deriving from the local part would refuse `sam@b.com` because
 * `sam@a.com` signed up first - a collision on a field neither of them chose.
 * The full address is unique by construction, and it is already what every
 * fixture and every store-compliance case in this library uses.
 *
 * The one remaining cast is the generic's: `Profile` may declare fields beyond
 * the base two, and only its caller knows them. It is a widening of a value that
 * now genuinely carries both required keys, not the `as unknown as` that used to
 * launder one missing them.
 */
function buildSignUpProfile<Profile extends Identities.ProfileMetadataBase>(
  initial: Record<string, unknown>,
  email: string,
): Profile {
  const supplied = initial.username
  const username = typeof supplied === 'string' && supplied.length > 0 ? supplied : email
  return { ...initial, email, username } as Profile
}

const SIGNUP_STAGE_VALUES: ReadonlySet<string> = new Set([
  'email-collected',
  'email-verified',
  'profile-completed',
  'mfa-enrolled',
  'terms-accepted',
  'completed',
])

function isSignUpStage(v: string): v is Flows.SignUpStage {
  return SIGNUP_STAGE_VALUES.has(v)
}

function parseSignUpFlow<Profile extends Identities.ProfileMetadataBase>(
  meta: unknown,
): Flows.SignUpFlowState<Profile> | null {
  if (!isPlainObject(meta)) return null
  // `purpose`, the one discriminator every flow writes. This row used to be the
  // odd one out with `kind`, which meant `getCredentialPurpose` - the helper the
  // deletes and the guards read - returned `undefined` for it.
  if (meta.purpose !== 'signup-flow') return null
  const flow = meta.flow
  if (!isPlainObject(flow)) return null
  if (typeof flow.id !== 'string' || flow.id.length === 0) return null
  if (typeof flow.identityId !== 'string' || flow.identityId.length === 0) return null
  if (!Array.isArray(flow.required)) return null
  if (!Array.isArray(flow.completed)) return null
  if (typeof flow.expiresAt !== 'number' || !Number.isFinite(flow.expiresAt)) return null
  if (typeof flow.absoluteExpiresAt !== 'number' || !Number.isFinite(flow.absoluteExpiresAt)) return null
  if (typeof flow.createdAt !== 'number' || !Number.isFinite(flow.createdAt)) return null
  const required: Flows.SignUpStage[] = []
  for (const s of flow.required) {
    if (typeof s !== 'string' || !isSignUpStage(s)) return null
    required.push(s)
  }
  const completed: Flows.SignUpStage[] = []
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
