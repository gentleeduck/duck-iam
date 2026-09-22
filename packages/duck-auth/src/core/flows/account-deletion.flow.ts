import { orNull } from '~/core/answer'
import {
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

export async function requestAccountDeletion<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.AccountDeletionRequestInput,
): Promise<{ ok: true }> {
  const ctx = deps.ctxFactory(opts.tenantId)
  const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
  const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/delete-account'
  if (opts.reason !== undefined && (typeof opts.reason !== 'string' || opts.reason.length > 1024)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'requestAccountDeletion: reason must be a string <=1024 chars',
    })
  }

  const identity = await orNull(ctx.stores.identities.find({ id: opts.identityId }))
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  // Below the lookup, like `requestEmailVerification`: an id with no row would otherwise spend a
  // bucket and page an operator about an account that does not exist. Moving it leaks nothing, since
  // an unknown id answers `AUTH_UNAUTHENTICATED` on either side.
  const limited = await ctx.limiter.consume(`account-delete:${opts.identityId}`)
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, identity.id)

  const channelKind = resolveChannelKind(opts.channel)
  const channelImpl = opts.channels[channelKind]
  if (!channelImpl) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `account-deletion: channel "${channelKind}" not configured`,
    })
  }

  // By purpose, the way `requestEmailVerification` does it, and for the same
  // reason: `recovery` is seven token families in one column.
  await ctx.stores.credentials.deleteByKindAndPurpose(
    opts.identityId,
    'recovery',
    RECOVERY_PURPOSES.accountDeletion,
    ctx.tenant,
  )

  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  await ctx.stores.credentials.create(
    toCredentialCreate({
      identityId: opts.identityId,
      kind: 'recovery',
      secret: tokenHash,
      metadata: {
        purpose: RECOVERY_PURPOSES.accountDeletion,
        ...(opts.reason !== undefined && { reason: opts.reason }),
      },
      expiresAt: new Date(Date.now() + ttlMs),
    }),
    ctx.tenant,
  )

  const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
  await deliver(ctx.events, 'account-deletion', channelImpl, {
    identity,
    templateId: 'account-deletion',
    vars: { url, ttlMin: Math.round(ttlMs / 60_000) },
    tenant: ctx.tenant,
  })
  return { ok: true }
}

/**
 * Confirm a deletion and mint the undo token, which is what makes the grace window reachable by the
 * account holder rather than only by an operator with an `authorize` callback.
 */
export async function completeAccountDeletion<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  input: Flows.AccountDeletionCompleteInput,
): Promise<{
  identity: Identities.Me<Profile>
  identityId: string
  restorableUntil: number
  cancellationToken: string
}> {
  if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(input.tenantId)
  const hash = ctx.crypto.authSha256(input.token)
  const row = await orNull(ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant))
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== RECOVERY_PURPOSES.accountDeletion) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }

  // The CAS claim burns the token in the same write, so the claim alone refuses a second completion
  // reading between here and the delete below. Until now that was caught one line later instead, by
  // `softDelete` reporting an already-hidden row as a miss - a guard in another file, for another reason.
  const burnt = ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
  try {
    await ctx.stores.credentials.rotate(row.id, burnt, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    throw err
  }
  const identityId = row.identityId
  const identity = await deps.identities.softDelete(identityId).orNull()
  // A valid token whose identity was erased has nothing left to delete, and reporting success would
  // tell the caller one happened.
  if (!identity) throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  await deps.sessions.revokeAllForIdentity(identityId)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  // Read off the row the store wrote rather than from a second clock reading: `deletedAt` is when the
  // grace window closes, so the deadline reported here is the one restore is measured against.
  const restorableUntil = identity.deletedAt?.getTime() ?? Date.now() + deps.identities.softDeleteGracePeriodMs

  const cancellationToken = ctx.crypto.authRandomToken(32)
  await ctx.stores.credentials.create(
    toCredentialCreate({
      identityId,
      kind: 'recovery',
      secret: ctx.crypto.authSha256(cancellationToken),
      metadata: { purpose: RECOVERY_PURPOSES.accountDeletionCancel },
      expiresAt: new Date(restorableUntil),
    }),
    ctx.tenant,
  )

  const channelKind = resolveChannelKind(input.channel)
  const channelImpl = input.channels?.[channelKind]
  if (channelImpl) {
    const callbackPath = isSafeCallbackPath(input.callbackPath) ? input.callbackPath : '/auth/cancel-deletion'
    const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(cancellationToken)}`
    await deliver(ctx.events, 'account-deletion-cancel', channelImpl, {
      identity,
      templateId: 'account-deletion-cancel',
      vars: { url, restorableUntil, ttlMin: Math.max(0, Math.round((restorableUntil - Date.now()) / 60_000)) },
      tenant: ctx.tenant,
    })
  }
  return { identity, identityId, restorableUntil, cancellationToken }
}

/** Undo a deletion inside the grace window, through exactly one of two gates: the undo token
 *  `completeAccountDeletion` minted, or an `authorize` callback. Both or neither is refused as a
 *  wiring mistake, or a bad token would fall back to a callback that says yes. */
export async function cancelAccountDeletion<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  input: Flows.AccountDeletionCancelInput,
): Promise<{ identity: Identities.Me<Profile>; identityId: string }> {
  const byToken = input.token !== undefined
  const byAuthorize = input.identityId !== undefined || input.authorize !== undefined
  if (byToken && byAuthorize) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'cancelAccountDeletion: pass a token or an authorize(identityId) callback, not both',
    })
  }
  if (!byToken && !byAuthorize) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'cancelAccountDeletion: pass a token or an authorize(identityId) callback',
    })
  }
  if (byToken) return cancelByToken(deps, input.token, input.tenantId)
  if (typeof input.identityId !== 'string' || input.identityId.length === 0 || input.identityId.length > 256) {
    throw new AuthError('AUTH_UNAUTHENTICATED')
  }
  // A missing callback is a wiring mistake, not a failed authentication, so it reports as one.
  // Without it an id alone un-deletes any account, for anyone who can reach the function.
  if (typeof input.authorize !== 'function') {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'cancelAccountDeletion: an authorize(identityId) callback is required',
    })
  }
  // Before the read, before the write. A refusal is reported with the same code
  // as an id that does not exist, so this cannot be used to ask which accounts
  // are sitting in the deletion grace window.
  if (!(await input.authorize(input.identityId))) {
    throw new AuthError('AUTH_UNAUTHENTICATED')
  }
  const identity = await deps.identities.restore(input.identityId).orNull()
  // `orNull` reads a missing id back as a value; at the flow boundary it is still an error, since the
  // caller named an account by id and there is none whose deletion this could cancel.
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
  return { identity, identityId: input.identityId }
}

/** The token branch of {@link cancelAccountDeletion}. The token names its own subject, so nothing
 *  here reads an id from the caller and an undo link cannot be pointed at another account. Deleted
 *  before the restore, so a restore that throws leaves no live token for a retry that fails alike. */
async function cancelByToken<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  token: string,
  tenantId: string | undefined,
): Promise<{ identity: Identities.Me<Profile>; identityId: string }> {
  if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  const ctx = deps.ctxFactory(tenantId)
  const hash = ctx.crypto.authSha256(token)
  const row = await orNull(ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant))
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== RECOVERY_PURPOSES.accountDeletionCancel) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }
  const identityId = row.identityId
  // The delete is the claim: it is exclusive, refusing a row another cancellation already took, so one
  // of two racing on a token gets through and one does not. Its `AUTH_CREDENTIAL_NOT_FOUND` is remapped
  // because that code is in `ABSENT`, and a caller with `orNull` would otherwise read a lost race as
  // "there is no such token" - the one answer a spent undo link must not give.
  try {
    await ctx.stores.credentials.delete(row.id, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_CREDENTIAL_NOT_FOUND') {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    throw err
  }
  const identity = await deps.identities.restore(identityId).orNull()
  // A row that went between the read above and the restore. An *erased* identity
  // does not reach here: erase cascades to the credential table, so its undo
  // token is already gone and the lookup above answered "invalid".
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
  return { identity, identityId }
}

/** `email` unless the caller named another configured kind. */
function resolveChannelKind(requested: 'email' | 'sms' | 'webpush' | undefined): 'email' | 'sms' | 'webpush' {
  return requested === 'sms' || requested === 'webpush' ? requested : 'email'
}
