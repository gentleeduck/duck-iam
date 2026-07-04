/**
 * Password-reset flow extracted from FlowsFacet. Two phases:
 *
 *   - `requestPasswordReset` - mints + dispatches a single-use token via the
 *     configured channel. Enumeration-safe: always returns `{ ok: true }`.
 *   - `completePasswordReset` - verifies the token, sets the new password,
 *     revokes every other session, and enforces MFA step-up when the
 *     identity has TOTP enrolled.
 */

import { isCredentialExpired, isRevoked } from '../../credential-utils'
import { AuthError } from '../../errors'
import type { Channel } from '../../types/infra'
import { isSafeCallbackPath } from '../../url-validators'
import type { FlowsFacet } from '../flows'

export async function requestPasswordReset<Profile>(
  deps: FlowsFacet.IDeps<Profile>,
  opts: {
    input: FlowsFacet.IPasswordResetRequestInput
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    channels: Partial<Record<'email' | 'sms' | 'webpush', Channel.IChannel>>
    tenantId?: string
  },
): Promise<{ ok: true }> {
  const { email } = opts.input
  const requestedChannel = opts.input.channel ?? 'email'
  const channelKind: 'email' | 'sms' | 'webpush' =
    requestedChannel === 'email' || requestedChannel === 'sms' || requestedChannel === 'webpush'
      ? requestedChannel
      : 'email'
  const ttlMs = opts.input.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.input.callbackPath) ? opts.input.callbackPath : '/auth/reset-password'
  const ctx = deps.ctxFactory(opts.tenantId)
  if (typeof email !== 'string' || email.length === 0 || email.length > 254) {
    return { ok: true }
  }

  const emailCanonical = email.trim().toLowerCase()
  const limited = await ctx.limiter.consume(`recovery:password:${emailCanonical}`)
  if (!limited.ok) {
    throw new AuthError('AUTH_RATE_LIMITED', {
      retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
    })
  }

  const identity = await opts.findIdentityByEmail(emailCanonical, opts.tenantId)
  if (!identity) {
    ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
    return { ok: true }
  }

  const channel = opts.channels[channelKind]
  if (!channel) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `password-reset: channel "${channelKind}" not configured`,
    })
  }

  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  await ctx.stores.credentials.upsert(
    {
      identityId: identity.id,
      kind: 'recovery',
      secret: tokenHash,
      metadata: { kind: 'password-reset', email },
      expiresAt: new Date(Date.now() + ttlMs),
    },
    ctx.tenant,
  )

  const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
  const identityRow = await ctx.stores.identities.findById(identity.id, ctx.tenant)
  if (!identityRow) {
    return { ok: true }
  }
  const requiresMfa = await deps.mfa.hasTotp(identity.id, ctx.tenant)
  void channel
    .send({
      identity: identityRow,
      templateId: 'password-reset',
      vars: { url, ttlMin: Math.round(ttlMs / 60_000), requiresMfa },
      tenant: ctx.tenant,
    })
    .then(async (result) => {
      if (!result.ok) {
        await deps.events.emit('signin.failed', {
          providerId: 'password-reset',
          reason: 'channel.send rejected delivery',
        })
      }
    })
    .catch(async (err) => {
      await deps.events.emit('signin.failed', {
        providerId: 'password-reset',
        reason: `channel.send threw: ${err instanceof Error ? err.message : String(err)}`,
      })
    })
  await deps.events.emit('recovery.password.requested', { identityId: identity.id })
  return { ok: true }
}

export async function completePasswordReset<Profile>(
  deps: FlowsFacet.IDeps<Profile>,
  input: FlowsFacet.IPasswordResetCompleteInput & { currentSid?: string; tenantId?: string },
): Promise<{ ok: true }> {
  const { token, newPassword } = input
  if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(input.tenantId)
  const hash = ctx.crypto.authSha256(token)
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row)) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  const meta = isPlainObject(row.metadata) && typeof row.metadata.kind === 'string' ? row.metadata : null
  if (meta?.kind !== 'password-reset') {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }
  if (await deps.mfa.hasTotp(row.identityId, ctx.tenant)) {
    if (!input.currentSid) {
      throw new AuthError('AUTH_RECOVERY_REQUIRES_MFA', { methods: ['totp'] })
    }
    const currentSession = await deps.sessions.getBySid(input.currentSid)
    if (!currentSession || currentSession.aal < 2 || !currentSession.fresh) {
      throw new AuthError('AUTH_RECOVERY_REQUIRES_MFA', { methods: ['totp'] })
    }
  }

  try {
    await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    throw err
  }
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)
  await deps.passwords.set(row.identityId, newPassword, ctx.tenant)
  await deps.sessions.revokeAllForIdentity(row.identityId)
  await deps.events.emit('recovery.password.completed', { identityId: row.identityId })
  return { ok: true }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
