import { getCredentialPurpose, isCredentialExpired, isRevoked, toCredentialUpsert } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'
import type { Identity } from '~/core/types'
import { isSafeCallbackPath } from '~/core/url-validators'
import type { FlowsFacet } from '../flows.facet'

export async function requestAccountDeletion<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  opts: FlowsFacet.AccountDeletionRequestInput,
): Promise<{ ok: true }> {
  const ctx = deps.ctxFactory(opts.tenantId)
  const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/delete-account'
  if (opts.reason !== undefined && (typeof opts.reason !== 'string' || opts.reason.length > 1024)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'requestAccountDeletion: reason must be a string <=1024 chars',
    })
  }

  const limited = await ctx.limiter.consume(`account-delete:${opts.identityId}`)
  if (!limited.ok) {
    throw new AuthError('AUTH_RATE_LIMITED', {
      retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
    })
  }

  const identity = await ctx.stores.identities.findById(opts.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  const requestedChannel = opts.channel ?? 'email'
  const channelKind: 'email' | 'sms' | 'webpush' =
    requestedChannel === 'email' || requestedChannel === 'sms' || requestedChannel === 'webpush'
      ? requestedChannel
      : 'email'
  const channelImpl = opts.channels[channelKind]
  if (!channelImpl) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `account-deletion: channel "${channelKind}" not configured`,
    })
  }

  const existing = await ctx.stores.credentials.listByIdentity(opts.identityId, 'recovery', ctx.tenant)
  for (const row of existing) {
    if (getCredentialPurpose(row) === 'account-deletion') {
      await ctx.stores.credentials.delete(row.id, ctx.tenant)
    }
  }

  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  await ctx.stores.credentials.upsert(
    toCredentialUpsert({
      identityId: opts.identityId,
      kind: 'recovery',
      secret: tokenHash,
      metadata: {
        purpose: 'account-deletion',
        ...(opts.reason !== undefined && { reason: opts.reason }),
      },
      expiresAt: new Date(Date.now() + ttlMs),
    }),
    ctx.tenant,
  )

  const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
  await channelImpl.send({
    identity,
    templateId: 'account-deletion',
    vars: { url, ttlMin: Math.round(ttlMs / 60_000) },
    tenant: ctx.tenant,
  })
  return { ok: true }
}

export async function completeAccountDeletion<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  input: FlowsFacet.AccountDeletionCompleteInput,
): Promise<{ identityId: string; restorableUntil: number }> {
  if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(input.tenantId)
  const hash = ctx.crypto.authSha256(input.token)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== 'account-deletion') {
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
  const identityId = row.identityId
  await deps.identities.softDelete(identityId)
  await deps.sessions.revokeAllForIdentity(identityId)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  const restorableUntil = Date.now() + deps.identities.softDeleteGracePeriodMs
  return { identityId, restorableUntil }
}

export async function cancelAccountDeletion<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  input: FlowsFacet.AccountDeletionCancelInput,
): Promise<{ identityId: string }> {
  if (typeof input.identityId !== 'string' || input.identityId.length === 0 || input.identityId.length > 256) {
    throw new AuthError('AUTH_UNAUTHENTICATED')
  }
  await deps.identities.restore(input.identityId)
  return { identityId: input.identityId }
}
