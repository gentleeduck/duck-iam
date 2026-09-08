import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialUpsert,
} from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Identities } from '~/core/identities'
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

  // The only flow in the unit that never consumed the limiter - password reset,
  // email verification and account deletion all do. Without it one unauthenticated
  // request equals one permanent identity row, unbounded. Keyed on the address, the
  // same shape `requestPasswordReset` uses, so hammering one victim's address is
  // what gets capped.
  const emailCanonical = opts.email.trim().toLowerCase()
  const limited = await ctx.limiter.consume(`signup:begin:${emailCanonical}`)
  // No subject to name. This bucket guards an address that, by construction, has
  // no account behind it yet, so there is nothing for a `lockout` handler to page
  // about or lock; looking one up would only add a read to a refused request.
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)

  const initial = isPlainObject(opts.initialProfile) ? opts.initialProfile : {}
  // No cast. `ProfileMetadataBase` requires `username`, duck-auth's own Postgres
  // schema enforces it with a CHECK and a unique index, and this line used to
  // launder a profile without one past the type with `as unknown as Profile` -
  // so `beginSignUp({ email })`, the documented happy path, produced an INSERT
  // that the library's own adapter rejects. Nothing caught it because the sqlite
  // conformance DDL omits CHECK constraints and memory/Redis have no schema.
  const profile = buildSignUpProfile<Profile>(initial, opts.email)

  // The row is claimed, not minted, whenever one is already sitting on this
  // address doing nothing.
  //
  // `beginSignUp` writes an identity for an address nobody has proved they own,
  // which let an attacker park on `victim@corp.com` and collide with the real
  // owner's signup forever - the unique index on email means the second signup
  // cannot have a row of its own. Deferring the write was the plan; it is not
  // buildable, because the credential row holding the flow token is a NOT NULL
  // foreign key to the identity it would defer (`fk_auth_credentials_identity`,
  // every dialect).
  //
  // So the squat is disarmed instead of prevented: a row in exactly the state
  // `beginSignUp` leaves behind, and nothing else, is handed to the next signup
  // for that address. The attacker's parking spot becomes the real user's
  // account, and the state check is what keeps this from being a takeover of
  // somebody's real one - see `isAbandonedSignUp`.
  const existing = await ctx.stores.identities.findByEmail(emailCanonical)
  let identityId: string
  if (existing) {
    if (!(await isAbandonedSignUp(existing, ctx))) {
      // An established account. This is the one thing signup cannot hide: the
      // address is unique, so a second account for it is impossible and the
      // caller has to be told something. Every path that reaches here answers
      // with this single code rather than whatever unique-index error the
      // dialect raised, so the answer is deliberate and identical everywhere.
      // Closing it entirely needs what `requestPasswordReset` has - a channel to
      // answer through, so the "someone tried to sign up with your address" mail
      // goes to the owner and the caller gets the same reply either way - and a
      // channel is the host's to supply.
      throw new AuthError('AUTH_EMAIL_TAKEN')
    }
    // Kill the flow the previous attempt was holding. Two live tokens on one row
    // would let whoever started first finish the signup the second caller is
    // paying for.
    for (const c of await ctx.stores.credentials.listByIdentity(existing.id, 'recovery', {})) {
      if (!isRevoked(c) && getCredentialPurpose(c) === 'signup-flow') {
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
  // The same cap the identity row is held to. `flow.data` is profile data that
  // has not landed yet: it is staged in credential metadata, which has no size
  // limit of its own, for up to 24 hours and re-read on every stage. Checking it
  // only at `completeSignUp` - where it finally meets `identities.update` - meant
  // the bytes were already stored and already being served before anything
  // objected, which is exactly the amplification `profileMaxBytes` exists to stop.
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
  await ctx.stores.credentials.upsert(
    toCredentialUpsert({
      identityId,
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
  // Before either write, so an oversized patch is refused rather than stored.
  // `profilePatch` is caller-supplied and was bounded by nothing at all on this
  // path - each stage merged it into `flow.data` and wrote the result back into
  // credential metadata, so a signup could stage megabytes and re-read them on
  // every subsequent call.
  deps.identities.assertProfileWithinCap(next.data)

  // The version guard, then the metadata write. This used to be rotate, revoke,
  // re-upsert: three writes, no transaction, and the middle one destroys the
  // token. A failure after the revoke stranded the user mid-signup with a token
  // the store had already marked dead, and the recovery depended on `upsert`
  // re-accepting a secret hash that had just been revoked - keying semantics the
  // interface never promised.
  //
  // `rotate` with the row's own secret keeps the compare-and-set - a concurrent
  // `advanceSignUp` still loses on `expectedVersion` - without invalidating the
  // token, and `patchMetadata` is a single atomic merge. The worst outcome is now
  // a version bump whose stage did not record, which the user fixes by retrying
  // the same call with the same token.
  try {
    await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_SIGNUP_TOKEN_INVALID')
    }
    throw err
  }
  await ctx.stores.credentials.patchMetadata(row.id, { flow: next, purpose: 'signup-flow' }, ctx.tenant)
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
  // Through the facet. It performs the same merge this used to hand-roll, and it
  // enforces `profileMaxBytes` - which the raw store does not, so the one place
  // the staged profile finally met a size limit was the one place that skipped
  // it. Dropping the hand-rolled merge also drops its `as Profile`: the cast was
  // asserting that the union of a stored profile and a caller's patch is a
  // complete `Profile`, which nothing checked.
  // `identity` is stale past this line; listeners need the profile we just wrote.
  const merged = await deps.identities.updateProfile(identity.id, flow.data, identity.version)
  // The stage said the address was proven; the column never recorded it. Nothing
  // in this flow ever set `emailVerified`, so an account created through the
  // documented happy path stayed unverified for good - which now also means it
  // stayed reclaimable by `beginSignUp` forever, turning a stale column into a
  // way to take over finished accounts. Written here, from the stage the host
  // completed, so the row leaves the abandoned state the moment it stops being
  // abandoned.
  const settled = flow.completed.includes('email-verified')
    ? await deps.identities.markEmailVerified(identity.id)
    : merged
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)

  const factors = opts.factors ?? [{ method: 'magic-link', completedAt: new Date() }]
  const aal = opts.aal ?? 1
  const { session, sid, csrfToken } = await deps.sessions.rotateOrCreate({
    // `sign-up`, not `guest-promotion`. `previousSid` is optional here: most
    // signups arrive with no prior session at all, and calling those a promotion
    // made every rotation event describe a transition that never took place. The
    // revocation semantics are identical; the name is now true.
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
 * True only for a row in the exact state `beginSignUp` leaves behind: an
 * unverified address, no provider links, and no credential that is not a
 * `signup-flow` token or already revoked.
 *
 * The three checks are the whole safety argument. Reusing a row means the next
 * caller's `completeSignUp` mints a session for it, so anything short of
 * "carries nothing and proves nothing" would be an account takeover rather than
 * a squat reclaim: an unverified account with a password set is somebody's, and
 * so is one with a Google link or a TOTP secret. MFA backup codes are stored as
 * `kind: 'recovery'` too, under `purpose: 'mfa-backup-code'`, so they fail the
 * `=== 'signup-flow'` test below and read as established here, which is right.
 *
 * The credential read is deliberately unscoped (`{}`), not run under the
 * caller's tenant: identities are global while credentials are not, so a
 * tenant-scoped read would miss a password living in another tenant and call an
 * established account abandoned. Fail closed - look everywhere.
 *
 * The cost is that a genuine user who started a signup and has not finished can
 * have their in-progress flow taken by someone else who asks for the same
 * address. That is bounded by `signup:begin:<address>`, it ends at the address's
 * real owner because completing still requires proving control of it, and it is
 * strictly better than the alternative it replaces: a squat nobody can ever
 * clear.
 */
async function isAbandonedSignUp<Profile extends Identities.ProfileMetadataBase>(
  identity: Identities.Me<Profile>,
  ctx: Provider.Context<Profile>,
): Promise<boolean> {
  if (identity.emailVerified) return false
  if (identity.providers.length > 0) return false
  const credentials = await ctx.stores.credentials.listByIdentity(identity.id, null, {})
  return credentials.every((c) => isRevoked(c) || getCredentialPurpose(c) === 'signup-flow')
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
