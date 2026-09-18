import { orNull } from '~/core/answer'
import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialCreate,
} from '~/core/credentials/credentials'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import { canonicalEmail, type Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
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

  // Keyed on the address, the shape `requestPasswordReset` uses: without it one unauthenticated
  // request is one permanent identity row, unbounded.
  const emailCanonical = canonicalEmail(opts.email) ?? ''
  const limited = await ctx.limiter.consume(`signup:begin:${emailCanonical}`)
  // No subject to name. This bucket guards an address that, by construction, has
  // no account behind it yet, so there is nothing for a `lockout` handler to page
  // about or lock; looking one up would only add a read to a refused request.
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)

  const initial = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  // Totalled, not cast: `username` is required by the type, by a CHECK and by a unique index, and only
  // pg enforces it, the sqlite conformance DDL omitting CHECKs and memory and Redis having no schema.
  const profile = buildSignUpProfile<Profile>(initial, opts.email)

  // SECURITY: the row is claimed, not minted, when one is already sitting on this address doing
  // nothing. `beginSignUp` writes an identity for an unproven address, so a squatter could otherwise
  // park on `victim@corp.com` forever.
  const existing = await orNull(ctx.stores.identities.find({ email: opts.email }))
  let identityId: string
  if (existing) {
    if (!(await isAbandonedSignUp(existing, ctx))) {
      // WARN: the one thing signup cannot hide, since the address is unique and the caller has to be
      // told something. One code on every path, rather than whatever the dialect raised, so the answer
      // is identical everywhere.
      throw new AuthError('AUTH_EMAIL_TAKEN')
    }
    // Kill the flow the previous attempt was holding. Two live tokens on one row
    // would let whoever started first finish the signup the second caller is
    // paying for.
    for (const c of await ctx.stores.credentials.listByIdentity(existing.id, 'recovery', {})) {
      if (!isRevoked(c) && getCredentialPurpose(c) === RECOVERY_PURPOSES.signupFlow) {
        await ctx.stores.credentials.revoke(c.id, {})
      }
    }
    identityId = (await deps.identities.updateProfile(existing.id, profile, existing.version)).id
  } else {
    identityId = (
      await ctx.stores.identities.create({
        profile,
        providers: [],
        emailVerified: false,
      })
    ).id
  }

  const flowToken = ctx.crypto.authRandomToken(32)
  const flowTokenHash = ctx.crypto.authSha256(flowToken)
  const dataInit: Partial<Profile> = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  const data: Partial<Profile> = { ...dataInit, email: opts.email }
  // The cap the identity row is held to, applied where the bytes are actually staged: credential
  // metadata has no size limit of its own and is re-read on every stage for up to 24 hours.
  deps.identities.assertProfileWithinCap(data)
  const flow: Flows.SignUpFlowState<Profile> = {
    id: ctx.crypto.authRandomToken(8),
    identityId,
    required,
    completed: ['email-collected'],
    data,
    expiresAt: now + 30 * 60_000,
    absoluteExpiresAt: now + 24 * 60 * 60_000,
    createdAt: now,
  }
  await ctx.stores.credentials.create(
    toCredentialCreate({
      identityId,
      kind: 'recovery',
      secret: flowTokenHash,
      metadata: { flow, purpose: RECOVERY_PURPOSES.signupFlow },
      expiresAt: new Date(flow.absoluteExpiresAt),
    }),
    ctx.tenant,
  )
  return { flow, flowToken }
}

/** The live flow behind this token, through {@link liveSignUpFlow}. Every way of not being one rejects
 *  `AUTH_CREDENTIAL_NOT_FOUND`, which is in the absent set, so the facet's `orNull()` reads them all back as
 *  null the way this used to answer it. */
export async function getSignUpFlow<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  flowToken: string,
  tenantId?: string,
): Promise<Flows.SignUpFlowState<Profile>> {
  const { flow } = await liveSignUpFlow<Profile>(deps.ctxFactory(tenantId), flowToken, 'AUTH_CREDENTIAL_NOT_FOUND')

  return flow
}

/**
 * The live flow behind a token. A miss, a revoked row, an elapsed TTL — the credential's absolute cap or the
 * flow's own sliding window — and metadata that will not parse all mean one thing: there is no live flow here.
 * Spelled out separately by each of the three callers, the list drifted: only the read path checked either
 * deadline, so the two write paths, `completeSignUp` among them, took a token whose cap had passed. Nothing
 * sweeps an expired credential — the store contract has no `gc` — so that window had no end.
 *
 * `code` is the caller's, because `getSignUpFlow` answers `AUTH_CREDENTIAL_NOT_FOUND` so the facet's `orNull()`
 * reads it back as null, while the write paths name the token.
 */
async function liveSignUpFlow<Profile extends Identities.ProfileMetadataBase>(
  ctx: Provider.Context<Profile>,
  flowToken: string,
  code: 'AUTH_CREDENTIAL_NOT_FOUND' | 'AUTH_SIGNUP_TOKEN_INVALID',
): Promise<{ flow: Flows.SignUpFlowState<Profile>; row: Credential.Me }> {
  const hash = ctx.crypto.authSha256(flowToken)
  const row = await orNull(ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant))
  if (!row || isRevoked(row)) throw new AuthError(code)
  const flow = parseSignUpFlow<Profile>(row.metadata)
  // `parseSignUpFlow` answers null for metadata it cannot read, which used to leave `getSignUpFlow`'s
  // `| null` covering two unrelated things at once.
  if (flow === null) throw new AuthError(code)
  const now = Date.now()
  if (isCredentialExpired(row, now) || now >= flow.expiresAt) {
    // Cleanup after the decision, never the decision itself.
    await ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError(code)
  }

  return { flow, row }
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
  const { flow, row } = await liveSignUpFlow<Profile>(ctx, opts.flowToken, 'AUTH_SIGNUP_TOKEN_INVALID')

  const next: Flows.SignUpFlowState<Profile> = {
    ...flow,
    completed: flow.completed.includes(opts.stage) ? flow.completed : [...flow.completed, opts.stage],
    data: opts.profilePatch ? { ...flow.data, ...opts.profilePatch } : flow.data,
    expiresAt: Math.min(flow.absoluteExpiresAt, Date.now() + 30 * 60_000),
  }
  // Before either write, so a caller-supplied `profilePatch` is refused rather than stored.
  deps.identities.assertProfileWithinCap(next.data)

  // The version guard, then the metadata write, and no revoke between them: there is no transaction
  // here, so a failure after a revoke strands the user holding a token the store has marked dead.
  // `rotate` with the row's own secret keeps the compare-and-set without invalidating the token.
  try {
    await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
    }
    throw err
  }
  await ctx.stores.credentials.patchMetadata(row.id, { flow: next, purpose: RECOVERY_PURPOSES.signupFlow }, ctx.tenant)
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
  const { flow, row } = await liveSignUpFlow<Profile>(ctx, opts.flowToken, 'AUTH_SIGNUP_TOKEN_INVALID')

  const missing = flow.required.filter((stage) => !flow.completed.includes(stage))
  if (missing.length > 0) {
    throw new AuthError('AUTH_SIGNUP_INCOMPLETE', { missing })
  }

  const identity = await orNull(ctx.stores.identities.find({ id: flow.identityId }))
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  // A CAS claim that also burns the token, placed after the validation so a refused completion leaves
  // the token usable, and before the first write so every write below is covered by it. The revoke at
  // the end is not a claim: it is unconditional, so without this two concurrent completions both read a
  // live row, both run the whole tail, and both get a session.
  const burnt = ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
  try {
    await ctx.stores.credentials.rotate(row.id, burnt, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
    }
    throw err
  }

  // Through the facet, not the store: it is what enforces `profileMaxBytes`, and this is where the
  // staged profile is finally big enough to need it.
  // `identity` is stale past this line; listeners need the profile just written.
  const merged = await deps.identities.updateProfile(identity.id, flow.data, identity.version)
  // SECURITY: written from the stage the host completed, so the row leaves the abandoned state the
  // moment it stops being abandoned; an unrecorded `emailVerified` keeps it reclaimable forever.
  const settled = flow.completed.includes('email-verified')
    ? await deps.identities.markEmailVerified(identity.id)
    : merged
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)

  const factors = opts.factors ?? [{ method: 'magic-link', completedAt: new Date() }]
  const aal = opts.aal ?? 1
  const { session, sid, csrfToken } = await deps.sessions.rotateOrCreate({
    // `sign-up`, not `guest-promotion`. `previousSid` is optional here: most
    // signups arrive with no prior session at all, and calling those a promotion
    // made every rotation event describe a transition that never took place.
    purpose: 'sign-up',
    ...(opts.previousSid !== undefined && { previousSid: opts.previousSid }),
    identityId: flow.identityId,
    identity: settled,
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

/**
 * True only for a row in the exact state `beginSignUp` leaves behind: an unverified address, no
 * provider links, and no credential that is not a `signup-flow` token or already revoked.
 *
 * SECURITY: the three checks are the whole safety argument, because reusing a row means the next
 * caller's `completeSignUp` mints a session for it. Anything that carries or proves something, a
 * password, a Google link, a TOTP secret or an MFA backup code, reads as established, which is right.
 * The credential read is unscoped on purpose: identities are global while credentials are not, so a
 * tenant-scoped read would miss a password in another tenant and call the account abandoned.
 */
async function isAbandonedSignUp<Profile extends Identities.ProfileMetadataBase>(
  identity: Identities.Me<Profile>,
  ctx: Provider.Context<Profile>,
): Promise<boolean> {
  if (identity.emailVerified) return false
  if (identity.providers.length > 0) return false
  const credentials = await ctx.stores.credentials.listByIdentity(identity.id, null, {})
  return credentials.every((c) => isRevoked(c) || getCredentialPurpose(c) === RECOVERY_PURPOSES.signupFlow)
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * Total a caller's partial profile into one the identity store will accept. `username` is required by
 * the type and by the Postgres CHECK while `initialProfile` is optional, so it is derived here and
 * replaced by `completeSignUp` once the flow carries a real one.
 *
 * WARN: the whole address, not its local part. `username` has a unique index, so `sam@a.com` would
 * otherwise refuse `sam@b.com` on a field neither of them chose.
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
  // `purpose`, the one discriminator every flow writes. This row was the odd one out with `kind`, so
  // `getCredentialPurpose`, the helper the deletes and the guards read, answered `undefined` for it.
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
