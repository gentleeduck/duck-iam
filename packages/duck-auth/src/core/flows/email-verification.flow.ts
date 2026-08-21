import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialUpsert,
} from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
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

  const limited = await ctx.limiter.consume(`verify:email:${opts.identityId}`)
  if (!limited.ok) {
    throw new AuthError('AUTH_RATE_LIMITED', {
      retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
    })
  }

  const identity = await ctx.stores.identities.findById(opts.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  if (identity.emailVerified) {
    return { ok: true }
  }

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

  await ctx.stores.credentials.deleteByKind(opts.identityId, 'recovery', ctx.tenant)

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
): Promise<{ identityId: string }> {
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

  const identity = await ctx.stores.identities.findById(row.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  // The column, never the profile. `updateProfile` merges a caller-supplied patch without
  // filtering keys, so a profile flag is something the account holder can set on themselves.
  await ctx.stores.identities.update(identity.id, { emailVerified: true }, identity.version)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  return { identityId: row.identityId }
}
