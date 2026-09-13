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

  const identity = await ctx.stores.identities.find({ id: opts.identityId })
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  // Below the lookup, the way `requestEmailVerification` was already ordered.
  // An id with no row behind it used to spend a bucket and, now that a spent
  // bucket also emits `lockout`, would have paged an operator about an account
  // that does not exist. It leaks nothing to move: an unknown id answers
  // `AUTH_UNAUTHENTICATED` on either side of the limiter.
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
  await deleteCredentialsByPurpose(
    ctx.stores.credentials,
    opts.identityId,
    'recovery',
    RECOVERY_PURPOSES.accountDeletion,
    ctx.tenant,
  )

  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  await ctx.stores.credentials.upsert(
    toCredentialUpsert({
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
 * Confirm a deletion, and mint the undo token that makes the grace window
 * usable by the person whose account it is.
 *
 * Until this existed, `cancelAccountDeletion` had exactly one gate - an
 * `authorize` callback - which is the operator's route, not the user's. A user
 * clicking "undo" in their mail has no admin rights to authorize against, so the
 * grace window `restorableUntil` advertises was reachable only by asking support.
 *
 * The token is minted after the soft delete lands, so a delete that fails leaves
 * no undo behind, and expires exactly when the window does: `restore` refuses
 * past `deletedAt` anyway, and a token that outlives the thing it unlocks is a
 * credential that answers `AUTH_GRACE_EXPIRED` instead of refusing itself.
 *
 * Plaintext comes back once. Pass `channels` and the library mails it; omit
 * `channels` and it is the caller's to deliver - or to drop, which is how a host
 * that does not want undo turns it off, since nobody else ever holds it.
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
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== RECOVERY_PURPOSES.accountDeletion) {
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
  const identity = await deps.identities.softDelete(identityId)
  // A valid token whose identity has since been erased has nothing left to
  // delete. Reporting success would tell the caller a deletion happened.
  if (!identity) throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  await deps.sessions.revokeAllForIdentity(identityId)
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  // Read off the row the store actually wrote rather than taking a second
  // clock reading: `deletedAt` IS the moment the grace window closes, so the
  // deadline reported here is the one restore will be measured against.
  const restorableUntil = identity.deletedAt?.getTime() ?? Date.now() + deps.identities.softDeleteGracePeriodMs

  const cancellationToken = ctx.crypto.authRandomToken(32)
  await ctx.stores.credentials.upsert(
    toCredentialUpsert({
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

/**
 * Undo a deletion inside the grace window. Two gates, one of which must apply:
 * the undo token `completeAccountDeletion` minted (the user's route), or an
 * `authorize` callback (the operator's).
 *
 * Both, or neither, is a wiring mistake and is refused. Resolving "both" in favour of one gate
 * would mean a bad token silently falling back to a callback that says yes.
 */
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
  const identity = await deps.identities.restore(input.identityId)
  // The store reports "no such id" as data; at the flow boundary it is an
  // error - there is no account whose deletion this could be cancelling, and
  // the caller is asking about one by id.
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
  return { identity, identityId: input.identityId }
}

/**
 * The token branch of {@link cancelAccountDeletion}. The token names its own
 * subject, so nothing here reads an id from the caller: an undo link cannot be
 * pointed at an account other than the one it was minted for.
 *
 * Deleted rather than revoked once spent, and deleted before the restore rather
 * than after: a restore that throws (`AUTH_GRACE_EXPIRED`, or a profile clash
 * with somebody who took the freed address) must not leave a live token behind
 * for a second attempt that will fail the same way.
 */
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
  const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
  if (!row || isRevoked(row) || getCredentialPurpose(row) !== RECOVERY_PURPOSES.accountDeletionCancel) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }
  const identityId = row.identityId
  await ctx.stores.credentials.delete(row.id, ctx.tenant)
  const identity = await deps.identities.restore(identityId)
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
