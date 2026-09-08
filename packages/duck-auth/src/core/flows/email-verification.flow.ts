import {
  deleteCredentialsByPurpose,
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  RECOVERY_PURPOSES,
  toCredentialUpsert,
} from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Identities } from '~/core/identities'
import { isSafeCallbackPath } from '~/core/url-validators'
import type { Flows } from './flows.types'

export async function requestEmailVerification<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.EmailVerificationRequestInput,
): Promise<{ ok: true }> {
  const ctx = deps.ctxFactory(opts.tenantId)
  const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/verify-email'

  const identity = await ctx.stores.identities.findById(opts.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  if (identity.emailVerified) {
    return { ok: true }
  }

  // After the two answers that send nothing, not before. The bucket exists to
  // bound outbound mail, and both of the branches above return without any: an
  // unknown id and an already-verified address used to spend a real user's
  // resend budget on a request that could never have produced a message, so a
  // caller looping on a stale id could exhaust the quota of the account it
  // named. Neither early return leaks anything the limiter was hiding - an
  // unknown id reports `AUTH_UNAUTHENTICATED` either way, and "already
  // verified" reports success either way.
  const limited = await ctx.limiter.consume(`verify:email:${opts.identityId}`)
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, identity.id)

  const requestedChannel = opts.channel ?? 'email'
  const channel: 'email' | 'sms' | 'webpush' =
    requestedChannel === 'email' || requestedChannel === 'sms' || requestedChannel === 'webpush'
      ? requestedChannel
      : 'email'
  const channelImpl = opts.channels[channel]
  if (!channelImpl) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `email-verification: channel "${channel}" not configured`,
    })
  }

  // By purpose, never by kind. `recovery` is shared by six token families
  // (`RECOVERY_PURPOSES`) told apart only by `metadata.purpose`, and
  // `deleteByKind` cannot read metadata - so asking for a verification mail used
  // to throw the user out of an in-flight signup and silently void a pending
  // reset, deletion, backup-code set or trusted device. The write side
  // discriminated and the delete side did not; now both do.
  await deleteCredentialsByPurpose(
    ctx.stores.credentials,
    opts.identityId,
    'recovery',
    RECOVERY_PURPOSES.emailVerification,
    ctx.tenant,
  )

  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  await ctx.stores.credentials.upsert(
    toCredentialUpsert({
      identityId: opts.identityId,
      kind: 'recovery',
      secret: tokenHash,
      metadata: { purpose: 'email-verification' },
      expiresAt: new Date(Date.now() + ttlMs),
    }),
    ctx.tenant,
  )

  const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
  await channelImpl.send({
    identity,
    templateId: 'email-verification',
    vars: { url, ttlMin: Math.round(ttlMs / 60_000) },
    tenant: ctx.tenant,
  })
  return { ok: true }
}

export async function completeEmailVerification<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  input: Flows.EmailVerificationCompleteInput,
): Promise<{ identity: Identities.Me<Profile>; identityId: string }> {
  if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(input.tenantId)
  const hash = ctx.crypto.authSha256(input.token)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== 'email-verification') {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }

  try {
    await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    throw err
  }

  // Through the facet, not the raw store. `IdentitiesImpl` is where the profile
  // size cap and the stale-write retry live; a flow reaching past it to
  // `ctx.stores.identities.update` gets neither. It also owns the read of the
  // expected version, which is the whole point here: the token is already spent
  // by the line above, so a version bumped by a concurrent profile write has to
  // be absorbed rather than reported - there is no second click for the user to
  // make.
  const verified = await deps.identities.markEmailVerified(row.identityId)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  // The verified row, straight off the write that set the flag - a caller that
  // renders the account after verification should not have to read it back.
  return { identity: verified, identityId: row.identityId }
}
