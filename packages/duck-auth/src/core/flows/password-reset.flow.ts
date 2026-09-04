/**
 * Password-reset flow extracted from Flows. Two phases:
 *
 *   - `requestPasswordReset` - mints + dispatches a single-use token via the
 *     configured channel. Enumeration-safe: always returns `{ ok: true }`.
 *   - `completePasswordReset` - verifies the token, sets the new password,
 *     revokes every other session, and enforces MFA step-up when the
 *     identity has TOTP enrolled.
 */

import type { Channel } from '~/channels/channels.types'
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
import { isSafeCallbackPath } from '~/core/url-validators'
import { NO_IDENTITY_SENTINEL } from '~/providers/passwords/passwords.constants'
import type { Flows } from './flows.types'

export async function requestPasswordReset<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: {
    input: Flows.PasswordResetRequestInput
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    channels: Partial<Record<'email' | 'sms' | 'webpush', Channel.Channel>>
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
  // No subject, deliberately. Resolving this address means calling the host's
  // `findIdentityByEmail` - arbitrary code, unknown cost - on every refused
  // request to an unauthenticated endpoint, which is the one place that trade is
  // worst. And an exhausted reset bucket blocks a *delivery*, not an
  // authentication: nobody is locked out of anything by it. `authPassword`'s
  // sign-in bucket is where a flood against one address is worth paging about,
  // and that is the site that pays for the lookup.
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)

  // Hoisted above the identity lookup on purpose. Below it, this throw fired only
  // for an address that exists and returned `{ok:true}` for one that does not -
  // a misconfigured channel turned the endpoint into a plain-language oracle.
  // A missing channel is a wiring fault either way, so it cannot depend on who asked.
  const channel = opts.channels[channelKind]
  if (!channel) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `password-reset: channel "${channelKind}" not configured`,
    })
  }

  const identity = await opts.findIdentityByEmail(emailCanonical, opts.tenantId)

  // Both branches mint and hash a token, then make the same three store calls in
  // the same order. `passwords.ts` established this discipline with the same
  // sentinel: the unknown-address path has to cost what the known one costs, or
  // the response time answers the question the response body refuses to.
  // What is left asymmetric is one write against one read on the credentials
  // table - not the "one sha256 versus three round-trips" this branch used to be.
  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  const subjectId = identity ? identity.id : NO_IDENTITY_SENTINEL

  if (identity) {
    await ctx.stores.credentials.upsert(
      toCredentialUpsert({
        identityId: identity.id,
        kind: 'recovery',
        secret: tokenHash,
        // `purpose` only. This used to carry the raw address alongside it, a
        // second copy of PII in a table `identities.erase` has no reason to
        // sweep - so an erased account left its email sitting in credential
        // metadata until the row's TTL expired. Nothing ever read it back:
        // `completePasswordReset` resolves the identity from `row.identityId`.
        metadata: { purpose: 'password-reset' },
        expiresAt: new Date(Date.now() + ttlMs),
      }),
      ctx.tenant,
    )
  } else {
    // Same table, same tenant scope, one round trip. A write cannot be mirrored:
    // `auth_credentials.identity_id` is a foreign key, so there is no row to hang
    // a decoy on.
    await ctx.stores.credentials.listByIdentity(subjectId, 'recovery', ctx.tenant)
  }

  const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
  const identityRow = await ctx.stores.identities.findById(subjectId)
  const requiresMfa = await deps.requireMfa().hasTotp(subjectId, ctx.tenant)
  if (!identity || !identityRow) {
    return { ok: true }
  }
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

/**
 * Verify the single-use token, swap the password, and end every session the
 * old one could still be holding open.
 *
 * Answers with the intents the caller must execute. They are empty on the usual
 * path - a reset arrives from an email link with no session at all - and carry a
 * replacement bearer when the caller *was* signed in, because that case routes
 * through `rotateOrCreate({ purpose: 'credential-change' })` and comes back with
 * a session rather than nothing.
 */
export async function completePasswordReset<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  input: Flows.PasswordResetCompleteInput & { currentSid?: string; tenantId?: string },
): Promise<{ ok: true; intents: Provider.Intent[] }> {
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
  if (getCredentialPurpose(row) !== 'password-reset') {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }
  // The token resolves to an identity *id*, not to an identity. Without this the
  // reset rotates the token, writes a new password and emits
  // `recovery.password.completed` for an account that has since been deleted.
  // It could never produce a login - `findByEmail` and `findById` both hide the
  // row - but the write and the event both landed. Reported as an invalid token
  // rather than a distinct code, so a reset link is not a way to ask whether an
  // account still exists. `findById` filters soft-deleted rows, so a missing row
  // is exactly "deleted or erased".
  const identity = await ctx.stores.identities.findById(row.identityId)
  if (!identity) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }

  // Resolved once, and only counted as this identity's. The MFA gate below used
  // to accept any session that was AAL 2 and fresh, without asking whose it was:
  // an attacker holding a victim's reset token passed their OWN stepped-up
  // session and the victim's TOTP requirement evaporated. Every account with a
  // second factor was resettable by anyone who had a second factor of their own.
  const currentSession = input.currentSid === undefined ? null : await deps.sessions.getBySid(input.currentSid)
  const callerSession = currentSession?.identityId === row.identityId ? currentSession : null

  if (await deps.requireMfa().hasTotp(row.identityId, ctx.tenant)) {
    if (!callerSession || callerSession.aal < 2 || !callerSession.fresh) {
      // Bounded, then burnt. A failed gate cannot consume the token outright -
      // the documented flow is exactly to be refused here, step up, and call
      // again with the same token and a `currentSid` - but leaving it entirely
      // unconsumed made the endpoint retryable for the token's whole TTL. The
      // limiter is what tells a user finishing a step-up apart from a caller
      // grinding the gate; when it is spent, so is the token.
      const attempt = await ctx.limiter.consume(`recovery:password:mfa:${hash}`)
      if (!attempt.ok) {
        await ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
        await refuseRateLimited(ctx.events, attempt, row.identityId)
      }
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

  // Sessions first, password second. The other order left a window with the new
  // password live and the old sessions still open: if the revoke threw - a store
  // blip, a network drop - whoever was holding a session the reset was meant to
  // end kept it, and the account holder had no way to tell. Failing before the
  // password write is the harmless direction: nothing has changed, and the token
  // is spent, so the user asks for another link.
  //
  // A caller who is signed in rotates rather than merely being swept, which is
  // what `credential-change` is for and puts this transition back on the single
  // rotation path `sessions.ts` promises every privilege change takes. It mints
  // as well as sweeps, which is why the branch is conditional: the ordinary
  // reset arrives from an email link with no session, and minting one there
  // would turn a reset link into a way to sign in.
  let intents: Provider.Intent[] = []
  if (callerSession) {
    const rotated = await deps.sessions.rotateOrCreate({
      purpose: 'credential-change',
      previousSid: input.currentSid ?? '',
      identityId: row.identityId,
      identity,
      kind: callerSession.kind,
      aal: callerSession.aal,
      factors: callerSession.factors,
      ...(callerSession.tenantId !== null && { tenantId: callerSession.tenantId }),
    })
    intents = deps.transport.issue(rotated.sid, rotated.session, {
      absolute: false,
      csrfToken: rotated.csrfToken,
      fresh: true,
    })
  } else {
    await deps.sessions.revokeAllForIdentity(row.identityId)
  }

  await deps.requirePasswords().set(row.identityId, newPassword, ctx.stores.credentials)
  await deps.events.emit('recovery.password.completed', { identityId: row.identityId })
  return { intents, ok: true }
}
