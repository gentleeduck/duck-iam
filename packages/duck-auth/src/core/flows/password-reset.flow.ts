/** The password-reset flow: `requestPasswordReset` mints and dispatches a single-use token and is
 *  enumeration-safe, `completePasswordReset` verifies it, swaps the password, sweeps every other
 *  session and enforces a step-up when the identity has TOTP enrolled. */

import type { Channel } from '~/channels/channels.types'
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
import { canonicalEmail, type Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { isSafeCallbackPath } from '~/core/url-validators'
import type { MfaFacet } from '~/providers/mfa'
import { NO_IDENTITY_SENTINEL } from '~/providers/passwords/passwords.constants'
import type { Flows } from './flows.types'

/** The MFA facet when one is registered, a deployment without it having no second factor to require.
 *  Only the resolution is guarded; what `hasTotp` itself raises still travels. */
function optionalMfa<Profile extends Identities.ProfileMetadataBase>(deps: Flows.Deps<Profile>): MfaFacet | null {
  try {
    return deps.requireMfa()
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_PROVIDER_NOT_REGISTERED') return null
    throw err
  }
}

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

  const emailCanonical = canonicalEmail(email) ?? ''
  const limited = await ctx.limiter.consume(`recovery:password:${emailCanonical}`)
  // No subject, deliberately: resolving the address means running the host's `findIdentityByEmail` on
  // every refused request to an unauthenticated endpoint. An exhausted reset bucket blocks a delivery,
  // not an authentication, so the password provider's sign-in bucket is where a flood is worth paging about.
  if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)

  // Hoisted above the identity lookup on purpose. Below it, this throw fires only for an address that
  // exists and answers `{ok:true}` for one that does not, so a misconfigured channel turns the endpoint
  // into a plain-language oracle.
  const channel = opts.channels[channelKind]
  if (!channel) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `password-reset: channel "${channelKind}" not configured`,
    })
  }

  // Through `orNull`, so a host wiring `auth.identities.getByEmail` straight in keeps the silent branch
  // this path is built on. Anything that is not an absence still propagates.
  const identity = await orNull(opts.findIdentityByEmail(emailCanonical, opts.tenantId))

  // SECURITY: both branches mint and hash a token, then make the same three store calls in the same
  // order, or response time answers what the response body refuses to. What is left asymmetric is one
  // write against one read.
  const token = ctx.crypto.authRandomToken(32)
  const tokenHash = ctx.crypto.authSha256(token)
  const subjectId = identity ? identity.id : NO_IDENTITY_SENTINEL

  // Retire the tokens issued before this one, or ten requests leave ten working keys in ten inboxes.
  // By purpose, not by kind: `recovery` also holds MFA backup codes, trusted devices and verification
  // mail.
  await ctx.stores.credentials.deleteByKindAndPurpose(
    subjectId,
    'recovery',
    RECOVERY_PURPOSES.passwordReset,
    ctx.tenant,
  )

  if (identity) {
    await ctx.stores.credentials.create(
      toCredentialCreate({
        identityId: identity.id,
        kind: 'recovery',
        secret: tokenHash,
        // `purpose` only: the address here would be a second copy of PII that `identities.erase` has no
        // reason to sweep, and nothing reads it, the identity coming from `row.identityId`.
        metadata: { purpose: RECOVERY_PURPOSES.passwordReset },
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
  const identityRow = await orNull(ctx.stores.identities.find({ id: subjectId }))
  const requiresMfa = (await optionalMfa(deps)?.hasTotp(subjectId, ctx.tenant)) ?? false
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

/** Verify the single-use token, swap the password, and end every session the old one could still be
 *  holding open. The intents are empty on the usual email-link path and carry a replacement bearer
 *  when the caller was signed in, which routes through `rotateOrCreate({ purpose: 'credential-change' })`. */
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
  const row = await orNull(ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant))
  if (!row || isRevoked(row)) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (getCredentialPurpose(row) !== RECOVERY_PURPOSES.passwordReset) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }
  if (isCredentialExpired(row)) {
    void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
    throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
  }
  // The token resolves to an identity id, not an identity: without this the reset writes a password
  // and emits a completion for an account that has since been deleted. Reported as an invalid token
  // rather than a distinct code, so a reset link cannot ask whether an account still exists.
  const identity = await orNull(ctx.stores.identities.find({ id: row.identityId }))
  if (!identity) {
    throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
  }

  // SECURITY: resolved once and only counted as this identity's. A gate that takes any AAL 2 session
  // lets an attacker satisfy the victim's TOTP requirement with a stepped-up session of their own.
  const currentSession = input.currentSid === undefined ? null : await deps.sessions.getBySid(input.currentSid).orNull()
  const callerSession = currentSession?.identityId === row.identityId ? currentSession : null

  if (await optionalMfa(deps)?.hasTotp(row.identityId, ctx.tenant)) {
    if (!callerSession || callerSession.aal < 2 || !callerSession.fresh) {
      // Bounded, then burnt. A failed gate cannot consume the token outright, since being refused here,
      // stepping up and calling again is the documented flow, so the limiter is what tells that caller
      // from one grinding the gate. When it is spent, so is the token.
      const attempt = await ctx.limiter.consume(`recovery:password:mfa:${hash}`)
      if (!attempt.ok) {
        await ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
        await refuseRateLimited(ctx.events, attempt, row.identityId)
      }
      throw new AuthError('AUTH_RECOVERY_REQUIRES_MFA', { methods: ['totp'] })
    }
  }

  // The CAS claim burns the token in the same write. Rotating to `row.secret` would claim the version
  // while leaving the row findable by `hash` and unrevoked until the revoke below, and a second reset
  // reading in that window wins its own CAS - taking the password with it, after this one has already
  // swept the sessions.
  const burnt = ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
  try {
    await ctx.stores.credentials.rotate(row.id, burnt, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    throw err
  }
  await ctx.stores.credentials.revoke(row.id, ctx.tenant)

  // SECURITY: sessions first, password second. The other order leaves the new password live with the
  // old sessions still open if the revoke throws; failing before the write changes nothing and the
  // user asks for another link.
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

  // SECURITY: in this reset's tenant, like every other store call above. `set` defaults the context to
  // `{}`, and an undefined tenant is not "this tenant" - `inTenant` emits no filter at all.
  await deps.requirePasswords().set(row.identityId, newPassword, ctx.stores.credentials, ctx.tenant)
  await deps.events.emit('recovery.password.completed', { identityId: row.identityId })
  return { intents, ok: true }
}
