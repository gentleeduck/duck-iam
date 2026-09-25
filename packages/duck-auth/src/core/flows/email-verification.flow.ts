import { orNull } from '~/core/answer'
import {
  burnCredential,
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialCreate,
} from '~/core/credentials/credentials'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Identities } from '~/core/identities'
import { isSafeCallbackPath } from '~/core/url-validators'
import { deliver } from './flows.delivery'
import type { Flows } from './flows.types'

export async function requestEmailVerification<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.EmailVerificationRequestInput,
): Promise<{ ok: true }> {
  const ctx = deps.ctxFactory(opts.tenantId)
  const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/verify-email'

  const identity = await orNull(ctx.stores.identities.find({ id: opts.identityId }))
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  if (identity.emailVerified) {
    return { ok: true }
  }

  // After the two answers that send nothing, not before. The bucket exists to bound outbound mail and
  // both branches above return without any, so charging them spends a real user's resend budget on a
  // request that could never have produced a message, and a caller looping on a stale id exhausts the
  // named account's quota.
  const limited = await ctx.limiter.consume(`verify:email:${opts.identityId}`)
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, identity.id)

  if (!deps.deliver) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: 'email-verification: no `deliver` configured' })
  }

  // By purpose, never by kind. `recovery` is shared by six token families (`RECOVERY_PURPOSES`) told
  // apart only by `metadata.purpose`, and `deleteByKind` cannot read metadata, so asking for a
  // verification mail threw the user out of an in-flight signup and silently voided a pending reset,
  // deletion, backup-code set or trusted device.
  await ctx.stores.credentials.deleteByKindAndPurpose(
    opts.identityId,
    'recovery',
    RECOVERY_PURPOSES.emailVerification,
    ctx.tenant,
  )

  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  await ctx.stores.credentials.create(
    toCredentialCreate({
      identityId: opts.identityId,
      kind: 'recovery',
      secret: tokenHash,
      metadata: { purpose: RECOVERY_PURPOSES.emailVerification },
      expiresAt: new Date(Date.now() + ttlMs),
    }),
    ctx.tenant,
  )

  const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
  await deliver(ctx.events, 'email-verification', deps.deliver, {
    identity,
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
  const row = await orNull(ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant))
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== RECOVERY_PURPOSES.emailVerification) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }

  await burnCredential(ctx, row)

  // Through the facet, not the raw store. `IdentitiesImpl` is where the profile size cap and the
  // stale-write retry live, and a flow reaching past it to `ctx.stores.identities.update` gets
  // neither.
  const verified = await deps.identities.markEmailVerified(row.identityId)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  // The verified row, straight off the write that set the flag, so a caller rendering the account
  // after verification need not read it back.
  return { identity: verified, identityId: row.identityId }
}
