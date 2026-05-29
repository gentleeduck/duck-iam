import { getCredentialPurpose, isCredentialExpired, isProfileBooleanTrue, isRevoked } from '../../credential-utils'
import { AuthErrorObject } from '../../errors'
import { isSafeCallbackPath } from '../../url-validators'
import type { FlowsFacet } from '../flows'

export async function requestEmailVerification<Profile>(
  flows: FlowsFacet<Profile>,
  opts: FlowsFacet.IEmailVerificationRequestInput,
): Promise<{ ok: true }> {
  const ctx = flows._ctxFactory(opts.tenantId)
  const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/verify-email'

  const limited = await ctx.limiter.consume(`verify:email:${opts.identityId}`)
  if (!limited.ok) {
    throw new AuthErrorObject('AUTH/RATE_LIMITED', {
      retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
    })
  }

  const identity = await ctx.stores.identities.findById(opts.identityId, ctx.tenant)
  if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

  if (isProfileBooleanTrue(identity.profile, 'emailVerified')) {
    return { ok: true }
  }

  const channel = opts.channel ?? 'email'
  const channelImpl = opts.channels[channel]
  if (!channelImpl) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: `email-verification: channel "${channel}" not configured`,
    })
  }

  await ctx.stores.credentials.deleteByKind(opts.identityId, 'recovery', ctx.tenant)

  const token = ctx.crypto.randomToken(32)
  const tokenHash = ctx.crypto.sha256(token)
  const now = Date.now()
  await ctx.stores.credentials.upsert(
    {
      identityId: opts.identityId,
      kind: 'recovery',
      secret: tokenHash,
      metadata: { purpose: 'email-verification' },
      expiresAt: now + ttlMs,
    },
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

export async function completeEmailVerification<Profile>(
  flows: FlowsFacet<Profile>,
  input: FlowsFacet.IEmailVerificationCompleteInput,
): Promise<{ identityId: string }> {
  if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
    throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
  }
  const ctx = flows._ctxFactory(input.tenantId)
  const hash = ctx.crypto.sha256(input.token)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  const now = Date.now()
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== 'email-verification') {
    throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row, now)) {
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

  const identity = await ctx.stores.identities.findById(row.identityId, ctx.tenant)
  if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

  const baseProfile = isPlainObject(identity.profile) ? identity.profile : {}
  const mergedProfile: Profile = { ...baseProfile, emailVerified: true } as Profile
  await ctx.stores.identities.update(identity.id, { profile: mergedProfile }, identity.version, ctx.tenant)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  return { identityId: row.identityId }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
