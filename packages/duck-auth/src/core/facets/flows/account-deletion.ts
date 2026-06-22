import { getCredentialPurpose, isCredentialExpired, isRevoked } from '../../credential-utils'
import { AuthErrorObject } from '../../errors'
import type { AuthTenantContext } from '../../types/context'
import { isSafeCallbackPath } from '../../url-validators'
import type { FlowsFacet } from '../flows'

export async function requestAccountDeletion<Profile>(
  flows: FlowsFacet<Profile>,
  opts: FlowsFacet.IAccountDeletionRequestInput,
): Promise<{ ok: true }> {
  const ctx = flows._ctxFactory(opts.tenantId)
  const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/delete-account'
  if (opts.reason !== undefined && (typeof opts.reason !== 'string' || opts.reason.length > 1024)) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'requestAccountDeletion: reason must be a string <=1024 chars',
    })
  }

  const limited = await ctx.limiter.consume(`account-delete:${opts.identityId}`)
  if (!limited.ok) {
    throw new AuthErrorObject('AUTH/RATE_LIMITED', {
      retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
    })
  }

  const identity = await ctx.stores.identities.findById(opts.identityId, ctx.tenant)
  if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

  const requestedChannel = opts.channel ?? 'email'
  const channelKind: 'email' | 'sms' | 'webpush' =
    requestedChannel === 'email' || requestedChannel === 'sms' || requestedChannel === 'webpush'
      ? requestedChannel
      : 'email'
  const channelImpl = opts.channels[channelKind]
  if (!channelImpl) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
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
  const now = Date.now()
  await ctx.stores.credentials.upsert(
    {
      identityId: opts.identityId,
      kind: 'recovery',
      secret: tokenHash,
      metadata: {
        purpose: 'account-deletion',
        ...(opts.reason !== undefined && { reason: opts.reason }),
      },
      expiresAt: now + ttlMs,
    },
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

export async function completeAccountDeletion<Profile>(
  flows: FlowsFacet<Profile>,
  input: FlowsFacet.IAccountDeletionCompleteInput,
): Promise<{ identityId: string; restorableUntil: number }> {
  if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
    throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
  }
  const ctx = flows._ctxFactory(input.tenantId)
  const hash = ctx.crypto.authSha256(input.token)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== 'account-deletion') {
    throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_EXPIRED')
  }

  try {
    await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthErrorObject && err.code === 'AUTH/STALE_WRITE') {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    throw err
  }
  const identityId = row.identityId
  await flows._identities.softDelete(identityId, ctx.tenant)
  await flows._sessions.revokeAllForIdentity(identityId)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  const restorableUntil = Date.now() + flows._identities.softDeleteGracePeriodMs
  return { identityId, restorableUntil }
}

export async function cancelAccountDeletion<Profile>(
  flows: FlowsFacet<Profile>,
  input: FlowsFacet.IAccountDeletionCancelInput,
): Promise<{ identityId: string }> {
  if (typeof input.identityId !== 'string' || input.identityId.length === 0 || input.identityId.length > 256) {
    throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
  }
  const tenant: AuthTenantContext = input.tenantId !== undefined ? { tenantId: input.tenantId } : {}
  await flows._identities.restore(input.identityId, tenant)
  return { identityId: input.identityId }
}
