import { getCredentialPurpose, isCredentialExpired, isProfileBooleanTrue, isRevoked } from '../credential-utils'
import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Events } from '../types/events'
import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'
import { isSafeCallbackPath } from '../url-validators'
import type { IdentitiesFacet } from './identities'
import type { MfaFacet } from './mfa'
import type { PasswordsFacet } from './passwords'
import type { ProvidersFacet } from './providers'
import type { SessionsFacet } from './sessions'

export const DEFAULT_FLOWS_CONFIG: FlowsFacet.IConfig = {
  signInPurpose: 'signin',
}

// --- Signup state machine -------------------------------------

// --- Impersonation -------------------------------------------

export class FlowsFacet<Profile = unknown> {
  constructor(
    private readonly _sessions: SessionsFacet,
    private readonly _identities: IdentitiesFacet<Profile>,
    private readonly _providers: ProvidersFacet<Profile>,
    private readonly _transport: Transport.ITransport,
    private readonly _events: Events.IBus,
    private readonly _ctxFactory: (tenantId?: string) => Provider.IContext<Profile>,
    private readonly _passwords: PasswordsFacet,
    private readonly _mfa: MfaFacet,
    private readonly _cfg: FlowsFacet.IConfig = DEFAULT_FLOWS_CONFIG,
  ) {}

  /**
   * Dispatch a sign-in via the named provider. Provider returns Intents;
   * the `startSession` intent is interpreted here (rotateOrCreate +
   * Transport.issue); other intents flow through to the caller.
   */
  async signIn(opts: FlowsFacet.ISignInOptions): Promise<FlowsFacet.ISignInOutcome> {
    if (!isProviderIdSafe(opts.providerId) || !this._providers.has(opts.providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: isProviderIdSafe(opts.providerId) ? opts.providerId : 'invalid',
        detail: 'unknown provider id',
      })
    }
    const ctx = this._ctxFactory(opts.tenantId)
    const intents = await this._providers.complete(opts.providerId, ctx, opts.input)

    const startIntent = intents.find(
      (i): i is Extract<Provider.Intent, { type: 'startSession' }> => i.type === 'startSession',
    )
    if (!startIntent) {
      // Provider completed without issuing a session (likely a requireMfa). Pass through.
      return { session: null, sid: '', intents }
    }

    const identity = await this._identities.getById(
      startIntent.identityId,
      opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
    )
    if (!identity) {
      throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    }

    const { session, sid, csrfToken } = await this._sessions.rotateOrCreate({
      purpose: opts.previousSid ? 're-auth' : this._cfg.signInPurpose,
      ...(opts.previousSid !== undefined && { previousSid: opts.previousSid }),
      identityId: startIntent.identityId,
      kind: 'user',
      aal: startIntent.aal,
      factors: startIntent.factors,
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      ...(opts.ip !== undefined && { ip: opts.ip }),
      ...(opts.userAgent !== undefined && { userAgent: opts.userAgent }),
    })

    const transportIntents = this._transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
    await this._events.emit('signin.success', {
      identity,
      factors: startIntent.factors,
    })
    return {
      session,
      sid,
      intents: [...intents.filter((i) => i.type !== 'startSession'), ...transportIntents],
    }
  }

  /**
   * Dispatch the `begin` phase of a provider. Wraps the same context
   * construction as `signIn` so callers (framework adapters, tests) don't
   * have to build it themselves.
   */
  async beginProvider(
    providerId: string,
    input: unknown,
    opts: { tenantId?: string } = {},
  ): Promise<Provider.Intent[]> {
    if (!isProviderIdSafe(providerId) || !this._providers.has(providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: isProviderIdSafe(providerId) ? providerId : 'invalid',
        detail: 'unknown provider id',
      })
    }
    return this._providers.begin(providerId, this._ctxFactory(opts.tenantId), input)
  }

  /** Revoke the current session and emit Transport.revoke intents. */
  async signOut(sid: string): Promise<{ intents: Provider.Intent[] }> {
    // sessions.revoke() also typeof-guards, but defending here means a non-string
    // sid never reaches the bus + transport (revoke remains a no-op).
    if (typeof sid === 'string' && sid.length > 0 && sid.length <= 4096) {
      await this._sessions.revoke(sid)
    }
    return { intents: this._transport.revoke() }
  }

  // --- Step-up flow -----------------------------------------

  /**
   * Check whether the current session satisfies a step-up requirement.
   * Returns `{satisfied: true}` (no-op) when the session already meets it;
   * otherwise returns a challenge enumerating the satisfying methods.
   */
  async checkStepUp(
    session: Session.ISession,
    requirement: FlowsFacet.IStepUpRequirement,
  ): Promise<FlowsFacet.IStepUpOutcome> {
    const requiredAal: Session.AAL = requirement.aal ?? 2
    const methods = requirement.methods ?? ['totp']
    const freshness = requirement.freshness

    if (session.aal >= requiredAal && session.fresh) {
      // Fail-closed: non-finite rotatedAt would slip the freshness gate.
      if (freshness !== undefined) {
        if (
          typeof session.rotatedAt !== 'number' ||
          !Number.isFinite(session.rotatedAt) ||
          Date.now() - session.rotatedAt > freshness
        ) {
          return { satisfied: false, reason: 'fresh-required', methods }
        }
      }
      return { satisfied: true, session, sid: '', intents: [] }
    }
    return { satisfied: false, reason: 'mfa-required', methods }
  }

  /**
   * Complete a step-up by verifying the supplied factor and rotating the
   * session to the higher AAL with the new factor recorded.
   */
  async completeStepUp(opts: {
    currentSid: string
    method: 'totp' | 'backup-code'
    code: string
    tenantId?: string
  }): Promise<{ session: Session.ISession; sid: string; intents: Provider.Intent[] }> {
    if (opts.method !== 'totp' && opts.method !== 'backup-code') {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    if (typeof opts.code !== 'string' || opts.code.length === 0 || opts.code.length > 64) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    const resolved = await this._sessions.getBySid(opts.currentSid)
    if (!resolved?.identityId) {
      throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    }
    const ok =
      opts.method === 'totp'
        ? await this._mfa.verifyTotp(
            resolved.identityId,
            opts.code,
            opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
          )
        : await this._mfa.verifyBackupCode(
            resolved.identityId,
            opts.code,
            opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
          )
    if (!ok) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    const { session, sid, csrfToken } = await this._sessions.rotateOrCreate({
      purpose: 'step-up',
      previousSid: opts.currentSid,
      identityId: resolved.identityId,
      kind: resolved.kind,
      aal: 2,
      factors: [
        ...resolved.factors,
        { method: opts.method === 'totp' ? 'totp' : 'backup-code', completedAt: Date.now() },
      ],
      ...(resolved.tenantId !== undefined && { tenantId: resolved.tenantId }),
    })
    const intents = this._transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
    return { session, sid, intents }
  }

  // --- Password reset ------------------------------------

  /**
   * Request a password reset. Always responds successfully (no enumeration);
   * if the identity exists, a single-use token is minted, hashed at rest,
   * and dispatched via the configured channel as a reset link.
   *
   * `channels` and `findIdentityByEmail` are passed in because the recovery
   * flow doesn't know which app-side wiring drives email lookup or message
   * delivery - depending on a magic-link provider would couple this facet to
   * one provider's options.
   */
  async requestPasswordReset(opts: {
    input: FlowsFacet.IPasswordResetRequestInput
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').Channel.IChannel>>
    tenantId?: string
  }): Promise<{ ok: true }> {
    const { email } = opts.input
    const channelKind = opts.input.channel ?? 'email'
    const ttlMs = opts.input.ttlMs ?? 30 * 60 * 1000
    // Silently fall back to a safe default on a hostile callbackPath
    // to preserve the enumeration-resistant ok-true contract.
    const callbackPath = isSafeCallbackPath(opts.input.callbackPath) ? opts.input.callbackPath : '/auth/reset-password'
    const ctx = this._ctxFactory(opts.tenantId)
    // RFC 5321 caps email at 254 chars; refuse and return ok-true.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) {
      return { ok: true }
    }

    // Canonical (trim + lowercase) so rate-limit + identity lookup share one key.
    const emailCanonical = email.trim().toLowerCase()
    const limited = await ctx.limiter.consume(`recovery:password:${emailCanonical}`)
    if (!limited.ok) {
      throw new AuthErrorObject('AUTH/RATE_LIMITED', {
        retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
      })
    }

    const identity = await opts.findIdentityByEmail(emailCanonical, opts.tenantId)
    if (!identity) {
      // Constant-time-ish padding: defer with a token-equivalent crypto op so the
      // unknown-email branch doesn't return noticeably faster.
      ctx.crypto.sha256(ctx.crypto.randomToken(32))
      return { ok: true }
    }

    const channel = opts.channels[channelKind]
    if (!channel) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `password-reset: channel "${channelKind}" not configured`,
      })
    }

    const token = ctx.crypto.randomToken(32)
    const tokenHash = ctx.crypto.sha256(token)
    const now = Date.now()
    await ctx.stores.credentials.upsert(
      {
        identityId: identity.id,
        kind: 'recovery',
        secret: tokenHash,
        metadata: { kind: 'password-reset', email },
        expiresAt: now + ttlMs,
      },
      ctx.tenant,
    )

    const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
    const identityRow = await ctx.stores.identities.findById(identity.id, ctx.tenant)
    if (!identityRow) {
      // Unlikely but possible (race): swallow + behave as enumeration-safe.
      return { ok: true }
    }
    // Fire-and-forget channel dispatch so the wire response shape and
    // latency are identical whether the email exists or not.
    const requiresMfa = await this._mfa.hasTotp(identity.id, ctx.tenant)
    void channel
      .send({
        identity: identityRow,
        templateId: 'password-reset',
        vars: { url, ttlMin: Math.round(ttlMs / 60_000), requiresMfa },
        tenant: ctx.tenant,
      })
      .then(async (result) => {
        if (!result.ok) {
          await this._events.emit('signin.failed', {
            providerId: 'password-reset',
            reason: 'channel.send rejected delivery',
          })
        }
      })
      .catch(async (err) => {
        await this._events.emit('signin.failed', {
          providerId: 'password-reset',
          reason: `channel.send threw: ${err instanceof Error ? err.message : String(err)}`,
        })
      })
    await this._events.emit('recovery.password.requested', { identityId: identity.id })
    return { ok: true }
  }

  /**
   * Complete a password reset by verifying the single-use token, setting
   * the new password, and revoking every other session for the identity.
   * If MFA is enrolled, callers must satisfy a step-up *before* hitting this
   * endpoint - the library refuses to swap passwords for accounts with MFA
   * unless a fresh AAL=2 session is passed via `currentSid`.
   */
  async completePasswordReset(
    input: FlowsFacet.IPasswordResetCompleteInput & { currentSid?: string; tenantId?: string },
  ): Promise<{ ok: true }> {
    const { token, newPassword } = input
    // 256-char cap to refuse multi-MB sha256 DoS.
    if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const ctx = this._ctxFactory(input.tenantId)
    const hash = ctx.crypto.sha256(token)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    const now = Date.now()
    if (!row || isRevoked(row)) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    // Recovery rows are kind-marked; without this, a verify token sets a password.
    const meta = row.metadata as { kind?: string } | undefined
    if (meta?.kind !== 'password-reset') {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    if (isCredentialExpired(row, now)) {
      void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_EXPIRED')
    }
    // Enforce MFA requirement when identity has TOTP enrolled.
    if (await this._mfa.hasTotp(row.identityId, ctx.tenant)) {
      if (!input.currentSid) {
        throw new AuthErrorObject('AUTH/RECOVERY_REQUIRES_MFA', { methods: ['totp'] })
      }
      const currentSession = await this._sessions.getBySid(input.currentSid)
      if (!currentSession || currentSession.aal < 2 || !currentSession.fresh) {
        throw new AuthErrorObject('AUTH/RECOVERY_REQUIRES_MFA', { methods: ['totp'] })
      }
    }

    // CAS-claim the row before issuing side effects to enforce
    // single-use under concurrent requests.
    try {
      await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
    } catch (err) {
      if (err instanceof AuthErrorObject && err.code === 'AUTH/STALE_WRITE') {
        throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
      }
      throw err
    }
    await ctx.stores.credentials.revoke(row.id, ctx.tenant)
    await this._passwords.set(row.identityId, newPassword, ctx.tenant)
    await this._sessions.revokeAllForIdentity(row.identityId)
    await this._events.emit('recovery.password.completed', { identityId: row.identityId })
    return { ok: true }
  }

  // --- Email verification ---------------------------------------------------

  /**
   * Mint + dispatch an email-verification token. Idempotent under the
   * rate-limit window: callers can re-trigger from a "didn't get the
   * email" button without flooding the channel.
   *
   * Behavior:
   *   - Generates a 256-bit random token; persists sha-256 under
   *     Credential.kind='recovery' with metadata.purpose='email-verification'
   *   - Per-identity rate limit at `verify:email:{identityId}` so
   *     resend pressure is bounded
   *   - No-op (returns { ok:true }) when the identity is already
   *     verified - avoids leaking "verified" status to the caller
   *   - Sends via the supplied channel with templateId='email-verification'
   */
  async requestEmailVerification(opts: FlowsFacet.IEmailVerificationRequestInput): Promise<{ ok: true }> {
    const ctx = this._ctxFactory(opts.tenantId)
    const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
    // see requestPasswordReset for rationale.
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

    // Replace any prior outstanding token so the user only ever has one live.
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

  /**
   * Verify the supplied token, mark `identity.profile.emailVerified=true`,
   * consume the token. Returns `{ identityId }` on success.
   */
  async completeEmailVerification(input: FlowsFacet.IEmailVerificationCompleteInput): Promise<{ identityId: string }> {
    // see completePasswordReset comment - same 256-char cap.
    if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const ctx = this._ctxFactory(input.tenantId)
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

    // CAS rotate enforces single-use against concurrent claims.
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

    const mergedProfile = {
      ...((identity.profile ?? {}) as Record<string, unknown>),
      emailVerified: true,
    } as Profile
    await ctx.stores.identities.update(identity.id, { profile: mergedProfile }, identity.version, ctx.tenant)
    await ctx.stores.credentials.delete(row.id, ctx.tenant)
    return { identityId: row.identityId }
  }

  // --- Account deletion -----------------------------------------------------

  /**
   * Request account deletion. Mints a confirmation token, dispatches
   * via the configured channel, does NOT touch the identity. Caller
   * confirms via {@link FlowsFacet.completeAccountDeletion}.
   *
   * The token is single-use + TTL'd (default 30 min). Multiple
   * outstanding deletion requests for the same identity get the prior
   * token wiped so only the latest verifies.
   */
  async requestAccountDeletion(opts: FlowsFacet.IAccountDeletionRequestInput): Promise<{ ok: true }> {
    const ctx = this._ctxFactory(opts.tenantId)
    const ttlMs = opts.ttlMs ?? 30 * 60 * 1000
    // see requestPasswordReset for rationale.
    const callbackPath = isSafeCallbackPath(opts.callbackPath) ? opts.callbackPath : '/auth/delete-account'
    // Bound the audit-log `reason` string at 1024 chars to protect
    // downstream log / webhook delivery from multi-MB end-user input.
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

    // Whitelist the channel kind so a hostile caller can't echo arbitrary
    // strings back through AUTH/MISCONFIGURED detail.
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

    // Replace any outstanding deletion token so the user only has one live.
    const existing = await ctx.stores.credentials.listByIdentity(opts.identityId, 'recovery', ctx.tenant)
    for (const row of existing) {
      if (getCredentialPurpose(row) === 'account-deletion') {
        await ctx.stores.credentials.delete(row.id, ctx.tenant)
      }
    }

    const token = ctx.crypto.randomToken(32)
    const tokenHash = ctx.crypto.sha256(token)
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

  /**
   * Confirm a pending account-deletion request. Validates the token,
   * triggers `IdentityStore.softDelete` (grace-period purge), revokes
   * every session for the identity, and emits `identity.merged` is NOT
   * used here - deletion is its own lifecycle.
   *
   * The actual hard-erase happens after the configured grace window;
   * the identity remains restorable via {@link FlowsFacet.cancelAccountDeletion}
   * until the grace expires.
   */
  async completeAccountDeletion(
    input: FlowsFacet.IAccountDeletionCompleteInput,
  ): Promise<{ identityId: string; restorableUntil: number }> {
    // see completePasswordReset comment - same 256-char cap.
    if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 256) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const ctx = this._ctxFactory(input.tenantId)
    const hash = ctx.crypto.sha256(input.token)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || isRevoked(row) || getCredentialPurpose(row) !== 'account-deletion') {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    if (isCredentialExpired(row)) {
      void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_EXPIRED')
    }

    // CAS rotate enforces single-use against concurrent claims.
    try {
      await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
    } catch (err) {
      if (err instanceof AuthErrorObject && err.code === 'AUTH/STALE_WRITE') {
        throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
      }
      throw err
    }
    const identityId = row.identityId
    await this._identities.softDelete(identityId, ctx.tenant)
    await this._sessions.revokeAllForIdentity(identityId)
    await ctx.stores.credentials.delete(row.id, ctx.tenant)
    const restorableUntil = Date.now() + this._identitiesGracePeriodMs()
    return { identityId, restorableUntil }
  }

  /**
   * Cancel a pending account deletion within the grace window. Calls
   * `IdentityStore.restore`; throws when the identity was already
   * hard-erased OR was never soft-deleted.
   */
  async cancelAccountDeletion(input: FlowsFacet.IAccountDeletionCancelInput): Promise<{ identityId: string }> {
    if (typeof input.identityId !== 'string' || input.identityId.length === 0 || input.identityId.length > 256) {
      throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    }
    const tenant: TenantContext = input.tenantId !== undefined ? { tenantId: input.tenantId } : {}
    await this._identities.restore(input.identityId, tenant)
    return { identityId: input.identityId }
  }

  /** Read the IdentitiesFacet's grace-period for reporting back to the caller. */
  private _identitiesGracePeriodMs(): number {
    return this._identities.softDeleteGracePeriodMs
  }

  // --- Signup state machine -----------------------------

  /**
   * Begin a multi-step signup. Creates the identity with
   * `profile.emailVerified=false` and returns a flow handle the caller
   * persists (cookie); each subsequent stage advances the handle until
   * `complete()` issues the session.
   *
   * Flows persist their state in the credentials store under
   * `kind: 'recovery'` + `metadata.kind: 'signup-flow'` so the existing
   * findByHashedSecret / expiresAt machinery applies for free.
   */
  async beginSignUp(opts: {
    email: string
    required?: FlowsFacet.ISignUpStage[]
    initialProfile?: Partial<Profile>
    tenantId?: string
  }): Promise<{ flow: FlowsFacet.ISignUpFlowState<Profile>; flowToken: string }> {
    if (typeof opts.email !== 'string' || opts.email.length === 0 || opts.email.length > 254) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    // Cap required-stages array so attacker can't bloat the signup-flow row.
    if (opts.required !== undefined && (!Array.isArray(opts.required) || opts.required.length > 16)) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'beginSignUp: required must be an array <=16' })
    }
    const ctx = this._ctxFactory(opts.tenantId)
    const now = Date.now()
    const required = opts.required ?? ['email-verified', 'terms-accepted']

    // The caller-supplied initialProfile must include any fields they consider
    // required on Profile. We layer the email + emailVerified flag on top.
    type EmailShape = { email: string; emailVerified: boolean }
    const profile = {
      ...(opts.initialProfile ?? ({} as Partial<Profile>)),
      email: opts.email,
      emailVerified: false,
    } as Partial<Profile> & EmailShape

    const created = await ctx.stores.identities.create(
      {
        profile: profile as Profile,
        providers: [],
        ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      },
      ctx.tenant,
    )

    const flowToken = ctx.crypto.randomToken(32)
    const flowTokenHash = ctx.crypto.sha256(flowToken)
    const flow: FlowsFacet.ISignUpFlowState<Profile> = {
      id: ctx.crypto.randomToken(8),
      identityId: created.id,
      required,
      completed: ['email-collected'],
      data: { ...(opts.initialProfile ?? ({} as Partial<Profile>)), email: opts.email } as Partial<Profile> &
        Pick<EmailShape, 'email'>,
      expiresAt: now + 30 * 60_000,
      absoluteExpiresAt: now + 24 * 60 * 60_000,
      createdAt: now,
    }
    await ctx.stores.credentials.upsert(
      {
        identityId: created.id,
        kind: 'recovery',
        secret: flowTokenHash,
        metadata: { kind: 'signup-flow', flow },
        expiresAt: flow.absoluteExpiresAt,
      },
      ctx.tenant,
    )
    return { flow, flowToken }
  }

  /** Read the current signup flow state from its plaintext token. */
  async getSignUpFlow(flowToken: string, tenantId?: string): Promise<FlowsFacet.ISignUpFlowState<Profile> | null> {
    const ctx = this._ctxFactory(tenantId)
    const hash = ctx.crypto.sha256(flowToken)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || isRevoked(row)) return null
    const now = Date.now()
    if (isCredentialExpired(row, now)) {
      await ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
      return null
    }
    // structural parser instead of `as` cast.
    // See parseSignUpFlow doc for the failure modes the cast masked.
    const flow = parseSignUpFlow<Profile>(row.metadata)
    if (flow === null) return null
    return flow
  }

  /** Advance the flow with new profile data; bumps the completed stage list. */
  async advanceSignUp(opts: {
    flowToken: string
    stage: FlowsFacet.ISignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  }): Promise<FlowsFacet.ISignUpFlowState<Profile>> {
    if (typeof opts.flowToken !== 'string' || opts.flowToken.length === 0 || opts.flowToken.length > 256) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    if (typeof opts.stage !== 'string' || opts.stage.length === 0 || opts.stage.length > 64) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    const ctx = this._ctxFactory(opts.tenantId)
    const hash = ctx.crypto.sha256(opts.flowToken)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || isRevoked(row)) throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    // structural parser; tampered flow row
    // (e.g. `required: []` to bypass stage verification) returns null.
    const flow = parseSignUpFlow<Profile>(row.metadata)
    if (flow === null) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    const next: FlowsFacet.ISignUpFlowState<Profile> = {
      ...flow,
      completed: flow.completed.includes(opts.stage) ? flow.completed : [...flow.completed, opts.stage],
      data: opts.profilePatch ? { ...flow.data, ...opts.profilePatch } : flow.data,
      expiresAt: Math.min(flow.absoluteExpiresAt, Date.now() + 30 * 60_000),
    }
    // CAS-claim the flow row before mutating so concurrent advances
    // serialise; the loser sees AUTH/SIGNUP_TOKEN_INVALID.
    try {
      await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
    } catch (err) {
      if (err instanceof AuthErrorObject && err.code === 'AUTH/STALE_WRITE') {
        throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
      }
      throw err
    }
    // Revoke the existing row so findByHashedSecret returns the new one next time.
    await ctx.stores.credentials.revoke(row.id, ctx.tenant)
    await ctx.stores.credentials.upsert(
      {
        identityId: flow.identityId,
        kind: 'recovery',
        secret: hash,
        metadata: { kind: 'signup-flow', flow: next },
        expiresAt: flow.absoluteExpiresAt,
      },
      ctx.tenant,
    )
    return next
  }

  /**
   * Finalise the signup. Validates that every required stage is in
   * `completed`; merges the accumulated profile into the identity; revokes
   * the flow credential; issues a fresh session.
   */
  async completeSignUp(opts: {
    flowToken: string
    aal?: Session.AAL
    factors?: Session.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    /**
     * pass the caller's current guest-session SID (when applicable).
     * The signup is a privilege-changing transition (anonymous -> user)
     * mandates EVERY such transition route through
     * `SessionsFacet.rotateOrCreate` so the prior SID gets revoked and
     * session fixation is structurally impossible. Without this the
     * pre-auth guest SID survives alongside the new user SID - an
     * attacker who planted the guest SID on the victim's browser
     * retains a valid post-signup handle.
     */
    previousSid?: string
  }): Promise<FlowsFacet.ISignInOutcome> {
    if (typeof opts.flowToken !== 'string' || opts.flowToken.length === 0 || opts.flowToken.length > 256) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    const ctx = this._ctxFactory(opts.tenantId)
    const hash = ctx.crypto.sha256(opts.flowToken)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || isRevoked(row)) throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    // structural parser closes signup-bypass
    // via tampered `flow.required: []` (would have made missing.length
    // === 0 trivially pass and completed the signup unverified).
    const flow = parseSignUpFlow<Profile>(row.metadata)
    if (flow === null) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    const missing = flow.required.filter((stage) => !flow.completed.includes(stage))
    if (missing.length > 0) {
      throw new AuthErrorObject('AUTH/SIGNUP_INCOMPLETE', { missing })
    }

    // Merge accumulated profile into identity row (version-bumped via update path).
    const identity = await ctx.stores.identities.findById(flow.identityId, ctx.tenant)
    if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    const mergedProfile = {
      ...((identity.profile ?? {}) as Partial<Profile>),
      ...flow.data,
    } as Profile
    await ctx.stores.identities.update(identity.id, { profile: mergedProfile }, identity.version, ctx.tenant)
    await ctx.stores.credentials.revoke(row.id, ctx.tenant)

    const factors = opts.factors ?? [{ method: 'magic-link', completedAt: Date.now() }]
    const aal = opts.aal ?? 1
    // rotateOrCreate atomically revokes prior guest SID on issuance.
    const { session, sid, csrfToken } = await this._sessions.rotateOrCreate({
      purpose: 'guest-promotion',
      ...(opts.previousSid !== undefined && { previousSid: opts.previousSid }),
      identityId: flow.identityId,
      kind: 'user',
      aal,
      factors,
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      ...(opts.ip !== undefined && { ip: opts.ip }),
      ...(opts.userAgent !== undefined && { userAgent: opts.userAgent }),
    })
    const intents = this._transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
    return { session, sid, intents }
  }

  // --- Impersonation ------------------------------------

  /**
   * Start an impersonation. Library refuses to issue an actingAs session
   * without first checking the caller's authorisation via the supplied
   * `authorize` callback. iam consumers wire engine.authorize() here; non-
   * iam apps supply their own predicate. NEVER pass `() => true` - that
   * defeats audit and DESIGN section 38's invariant.
   */
  async impersonate(
    opts: FlowsFacet.IImpersonateOptions & {
      authorize: (realSession: Session.ISession, targetIdentityId: string) => Promise<boolean>
    },
  ): Promise<FlowsFacet.IImpersonateOutcome> {
    if (
      typeof opts.targetIdentityId !== 'string' ||
      opts.targetIdentityId.length === 0 ||
      opts.targetIdentityId.length > 256
    ) {
      throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'invalid target' })
    }
    // Bound the audit-log `reason` at 256 chars to protect session
    // reads, OpenTelemetry payloads, and webhook deliveries.
    if (typeof opts.reason !== 'string' || opts.reason.length === 0 || opts.reason.length > 256) {
      throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'reason must be 1-256 chars' })
    }
    const real = await this._sessions.getBySid(opts.realSid)
    if (!real?.identityId) {
      throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    }
    // Refuse self-impersonation - would mask the audit trail.
    if (real.identityId === opts.targetIdentityId) {
      throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'cannot impersonate self' })
    }
    const allowed = await opts.authorize(real, opts.targetIdentityId)
    if (!allowed) {
      throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'authorize() returned false' })
    }

    const ttlMs = Math.min(opts.ttlMs ?? 60 * 60_000, 60 * 60_000)
    const now = Date.now()
    const target = await this._identities.getById(
      opts.targetIdentityId,
      opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
    )
    if (!target) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

    const { session, sid, csrfToken } = await this._sessions.rotateOrCreate({
      purpose: 'impersonate-start',
      previousSid: opts.realSid,
      identityId: opts.targetIdentityId,
      kind: 'user',
      aal: real.aal,
      factors: real.factors,
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      actingAs: {
        realIdentityId: real.identityId,
        startedAt: now,
        reason: opts.reason,
        expiresAt: now + ttlMs,
      },
    })
    await this._events.emit('identity.impersonated', {
      realIdentityId: real.identityId,
      targetIdentityId: opts.targetIdentityId,
      reason: opts.reason,
    })
    const intents = this._transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
    return { session, sid, intents }
  }

  // --- Account linking -----------------------------------------------------

  /**
   * Attach a provider link (`{ providerId, providerSub }`) to an
   * already-authenticated identity. Refuses when the (providerId,
   * providerSub) is already bound to a different identity to prevent
   * account hijack via the link flow.
   *
   * Caller is responsible for verifying the provider sub - i.e. the
   * caller should have just completed an OAuth dance against the IdP
   * and extracted the sub from the verified token. The facet does NOT
   * re-verify; it trusts the caller because the OAuth provider already
   * did the round-trip.
   *
   * Emits `identity.linked` on success.
   */
  async linkProvider(opts: FlowsFacet.ILinkProviderInput): Promise<{ identityId: string; providerId: string }> {
    // Defensive caps before adapter calls; both fields flow into the JSONB
    // providers array (SQL) + the AUTH/PROVIDER_FAILED meta echo.
    if (!isProviderIdSafe(opts.providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'invalid',
        detail: 'invalid providerId',
      })
    }
    if (typeof opts.providerSub !== 'string' || opts.providerSub.length === 0 || opts.providerSub.length > 512) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: opts.providerId,
        detail: 'invalid providerSub',
      })
    }
    const tenant: TenantContext = opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {}
    const identity = await this._identities.getById(opts.identityId, tenant)
    if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

    // Refuse when the sub already maps to a different identity.
    const existing = await this._ctxFactory(opts.tenantId).stores.identities.findByProviderSub(
      opts.providerId,
      opts.providerSub,
      tenant,
    )
    if (existing && existing.id !== opts.identityId) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: opts.providerId,
        detail: 'provider sub already linked to a different identity',
      })
    }

    // Idempotent: if the link already exists on this identity, no-op.
    const alreadyLinked = identity.providers.some(
      (p) => p.providerId === opts.providerId && p.providerSub === opts.providerSub,
    )
    if (alreadyLinked) {
      return { identityId: opts.identityId, providerId: opts.providerId }
    }

    await this._ctxFactory(opts.tenantId).stores.identities.link(
      opts.identityId,
      { providerId: opts.providerId, providerSub: opts.providerSub, addedAt: Date.now() },
      tenant,
    )
    await this._events.emit('identity.linked', {
      identityId: opts.identityId,
      providerId: opts.providerId,
    })
    return { identityId: opts.identityId, providerId: opts.providerId }
  }

  /**
   * Detach a provider link. Refuses to remove the LAST authentication
   * factor when no password / passkey credential remains - otherwise
   * the user would lock themselves out of the account.
   */
  async unlinkProvider(opts: FlowsFacet.IUnlinkProviderInput): Promise<{ identityId: string; providerId: string }> {
    if (!isProviderIdSafe(opts.providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'invalid',
        detail: 'invalid providerId',
      })
    }
    const tenant: TenantContext = opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {}
    const identity = await this._identities.getById(opts.identityId, tenant)
    if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

    const linked = identity.providers.filter((p) => p.providerId === opts.providerId)
    if (linked.length === 0) {
      // Idempotent no-op.
      return { identityId: opts.identityId, providerId: opts.providerId }
    }

    // Lockout guard: if removing this link would leave the identity
    // with zero credentials AND zero provider links, refuse.
    if (!opts.allowLockout) {
      const otherLinks = identity.providers.filter((p) => p.providerId !== opts.providerId)
      const ctx = this._ctxFactory(opts.tenantId)
      const credentials = await ctx.stores.credentials.listByIdentity(opts.identityId, undefined, tenant)
      const liveCredentials = credentials.filter(
        (c) => !isRevoked(c) && (c.kind === 'password' || c.kind === 'passkey'),
      )
      if (otherLinks.length === 0 && liveCredentials.length === 0) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: opts.providerId,
          detail: 'refusing to unlink the only authentication factor; pass allowLockout:true to override',
        })
      }
    }

    await this._ctxFactory(opts.tenantId).stores.identities.unlink(opts.identityId, opts.providerId, tenant)
    return { identityId: opts.identityId, providerId: opts.providerId }
  }

  // --- Impersonation continued --------------------------------------------

  /** End an impersonation; revoke the actingAs session, optionally restore the original SID. */
  async releaseImpersonation(impersonationSid: string): Promise<{ intents: Provider.Intent[] }> {
    const session = await this._sessions.getBySid(impersonationSid)
    if (!session?.actingAs) {
      throw new AuthErrorObject('AUTH/IMPERSONATE_EXPIRED')
    }
    await this._sessions.revoke(impersonationSid)
    // Framework adapter restores the real-session cookie if it kept the reference;
    // library cannot re-issue it because the plaintext sid lives in cookie space only.
    return { intents: this._transport.revoke() }
  }
}

const SIGNUP_STAGE_VALUES: ReadonlySet<string> = new Set([
  'email-collected',
  'email-verified',
  'profile-completed',
  'mfa-enrolled',
  'terms-accepted',
  'completed',
])

/**
 * structural parser for the signup-flow
 * metadata persisted under `recovery` credentials with
 * `metadata.kind === 'signup-flow'`. The prior `meta.flow as
 * FlowsFacet.ISignUpFlowState<Profile>` cast trusted whatever the
 * credential store returned. Concrete failures the cast masked:
 *
 *  - `flow.required: []` (tampered to remove required stages) ->
 *    `completeSignUp`'s `missing.length === 0` passes -> signup completes
 *    without ANY verification. Effective signup-bypass given adapter
 *    write access (threat-model adjacent: trusted persistence, but
 *    catches custom-migration accidents).
 *  - `flow.required: 'foo'` (string, not array) -> `.filter` throws
 *    TypeError -> HTTP 500 on every advanceSignUp / completeSignUp.
 *  - `flow.completed: 'abc'` (string) -> `[...flow.completed, stage]`
 *    spreads to `['a','b','c',stage]` -> the next stage check uses
 *    the wrong values. Signup state machine corrupted.
 *  - `flow.identityId: null` -> `findById(null, ...)` adapter behavior
 *    is undefined; might succeed-with-null or throw.
 *  - `flow.absoluteExpiresAt: 'never'` (string) -> `Math.min(string, n)`
 *    coerces to NaN; expiresAt becomes NaN; the slide-window logic
 *    silently breaks. Adjacent `isCredentialExpired` catches this on
 *    read (NaN -> expired) but the in-memory state is wrong.
 *
 * Per-stage validation: `required` + `completed` entries must be from
 * the closed ISignUpStage union. Unknown stage strings are dropped
 * from `completed` (we don't lose the row over an unknown completed
 * stage from a forward-compat upgrade), but a `required` array with
 * any unknown member rejects (any future stage MUST be required and
 * verified).
 *
 * Returns null on any structural failure; the caller throws
 * AUTH/SIGNUP_TOKEN_INVALID - same code the prior `meta?.kind !==
 * 'signup-flow' || !meta.flow` guard produced for missing kind.
 */
function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

function parseSignUpFlow<Profile>(meta: unknown): FlowsFacet.ISignUpFlowState<Profile> | null {
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) return null
  if (Reflect.get(meta, 'kind') !== 'signup-flow') return null
  const flow: unknown = Reflect.get(meta, 'flow')
  if (typeof flow !== 'object' || flow === null || Array.isArray(flow)) return null

  const id = Reflect.get(flow, 'id')
  if (typeof id !== 'string' || id.length === 0) return null
  const identityId = Reflect.get(flow, 'identityId')
  if (typeof identityId !== 'string' || identityId.length === 0) return null

  const requiredRaw = Reflect.get(flow, 'required')
  if (!Array.isArray(requiredRaw)) return null
  const required: FlowsFacet.ISignUpStage[] = []
  for (const s of requiredRaw) {
    if (typeof s !== 'string' || !SIGNUP_STAGE_VALUES.has(s)) return null
    // Type-narrow the string to the union via the predicate-style check.
    if (isSignUpStage(s)) required.push(s)
  }

  const completedRaw = Reflect.get(flow, 'completed')
  if (!Array.isArray(completedRaw)) return null
  const completed: FlowsFacet.ISignUpStage[] = []
  for (const s of completedRaw) {
    if (typeof s === 'string' && isSignUpStage(s)) completed.push(s)
  }

  const dataRaw = Reflect.get(flow, 'data')
  if (typeof dataRaw !== 'object' || dataRaw === null || Array.isArray(dataRaw)) return null

  const expiresAt = Reflect.get(flow, 'expiresAt')
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) return null
  const absoluteExpiresAt = Reflect.get(flow, 'absoluteExpiresAt')
  if (typeof absoluteExpiresAt !== 'number' || !Number.isFinite(absoluteExpiresAt)) return null
  const createdAt = Reflect.get(flow, 'createdAt')
  if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) return null

  // Build the result field-by-field - no `as` cast on the output. The
  // Profile generic is opaque to this parser; we accept whatever `data`
  // object the caller stored under `Partial<Profile>` shape.
  return {
    id,
    identityId,
    required,
    completed,
    data: dataRaw as Partial<Profile>,
    expiresAt,
    absoluteExpiresAt,
    createdAt,
  }
}

/** Type predicate for FlowsFacet.ISignUpStage. */
function isSignUpStage(v: string): v is FlowsFacet.ISignUpStage {
  return SIGNUP_STAGE_VALUES.has(v)
}

/**
 * Namespace merge for FlowsFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging.
 */
export namespace FlowsFacet {
  export interface IConfig {
    /** What `signIn` calls SessionsFacet.rotateOrCreate with by default. */
    signInPurpose: 'signin' | 're-auth'
  }

  export interface ISignInOptions {
    providerId: string
    input: unknown
    /** Currently-active SID (cookie or bearer); used by rotateOrCreate to revoke. */
    previousSid?: string
    ip?: string
    userAgent?: string
    tenantId?: string
  }

  export interface ISignInOutcome {
    /**
     * Persisted session row; `session.id` is the **hashed** row key. Null when
     * the provider issued no `startSession` intent (typically because it
     * returned `requireMfa` and the caller is mid-flow); in that case `sid`
     * is also empty and `intents` carries the provider's response.
     */
    session: Session.ISession | null
    /** Plaintext SID the client uses to authenticate; empty when `session` is null. */
    sid: string
    /** Intents the framework adapter must execute on the response. */
    intents: Provider.Intent[]
  }

  export interface IStepUpRequirement {
    /** Required AAL on the post-step-up session. Default 2. */
    aal?: Session.AAL
    /** Methods that satisfy the requirement (any-of). Default ['totp']. */
    methods?: Session.FactorMethod[]
    /** Recency window in ms - re-auth required if last factor older than this. */
    freshness?: number
  }

  export type IStepUpOutcome =
    | { satisfied: true; session: Session.ISession; sid: string; intents: Provider.Intent[] }
    | { satisfied: false; reason: 'mfa-required' | 'fresh-required'; methods: Session.FactorMethod[] }

  export interface IPasswordResetRequestInput {
    email: string
    /** Channel to use; default 'email'. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Path on the app that handles the reset; library appends `?token=`. */
    callbackPath?: string
    /** Optional override; default 30 minutes. */
    ttlMs?: number
  }

  export interface IPasswordResetCompleteInput {
    token: string
    newPassword: string
  }

  export interface ISignUpFlowState<Profile = unknown> {
    /** Opaque flow id; surfaced to the framework adapter to put on a __Host-duck-signup cookie. */
    id: string
    /** Identity row created at email-collected stage (profile.emailVerified=false until verifyEmail). */
    identityId: string
    /** Required stages (ordered); apps configure per signup type (passkey-only, B2B, etc.). */
    required: FlowsFacet.ISignUpStage[]
    /** Stages the user has already completed; library guarantees idempotent appends. */
    completed: FlowsFacet.ISignUpStage[]
    /** Accumulated profile across stages; merged into Identity.profile at complete(). */
    data: Partial<Profile>
    /** Sliding TTL (default 30 min). */
    expiresAt: number
    /** Hard cap (default 24 h); cannot be slid past. */
    absoluteExpiresAt: number
    /** Wall-clock created time, ms. */
    createdAt: number
  }

  export interface IImpersonateOptions {
    /** Caller's session id (the real subject). */
    realSid: string
    /** Identity being impersonated. */
    targetIdentityId: string
    /** Human-readable reason; audit-logged via `identity.impersonated` event. */
    reason: string
    /** TTL cap; default 1 hour, cannot exceed 1 hour even if overridden. */
    ttlMs?: number
    tenantId?: string
  }

  export interface IImpersonateOutcome {
    session: Session.ISession
    /** Plaintext SID for the new actingAs session (separate from real session). */
    sid: string
    intents: Provider.Intent[]
  }

  export type ISignUpStage =
    | 'email-collected'
    | 'email-verified'
    | 'profile-completed'
    | 'mfa-enrolled'
    | 'terms-accepted'
    | 'completed'

  export interface ILinkProviderInput {
    /** Identity to attach the provider link to. */
    identityId: string
    /** Provider id (`'google'`, `'github'`, etc). */
    providerId: string
    /** Provider-side subject id (verified by the OAuth dance the caller just completed). */
    providerSub: string
    /** Tenant scope. */
    tenantId?: string
  }

  export interface IUnlinkProviderInput {
    identityId: string
    providerId: string
    tenantId?: string
    /**
     * Set true to bypass the "would lock out the user" guard. Use only
     * during account deletion flows or admin overrides.
     */
    allowLockout?: boolean
  }

  export interface IEmailVerificationRequestInput {
    /** Identity to verify. */
    identityId: string
    /** Channel keyed by kind. Email is the typical default. */
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').Channel.IChannel>>
    /** Which channel to dispatch on; default 'email'. */
    channel?: 'email' | 'sms' | 'webpush'
    /** TTL of the verification token, ms. Default 30 minutes. */
    ttlMs?: number
    /** Callback path on the app; library appends `?token=`. Default `/auth/verify-email`. */
    callbackPath?: string
    tenantId?: string
  }

  export interface IEmailVerificationCompleteInput {
    /** Token plaintext as received from the verify link. */
    token: string
    tenantId?: string
  }

  export interface IAccountDeletionRequestInput {
    identityId: string
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').Channel.IChannel>>
    /** Channel kind to use; default `'email'`. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Token TTL in ms. Default 30 minutes. */
    ttlMs?: number
    /** Path on the app that handles the confirmation. Default `/auth/delete-account`. */
    callbackPath?: string
    /** Optional human-readable reason persisted in metadata; surfaces in audit log. */
    reason?: string
    tenantId?: string
  }

  export interface IAccountDeletionCompleteInput {
    /** Token from the confirmation link. */
    token: string
    tenantId?: string
  }

  export interface IAccountDeletionCancelInput {
    /** Identity to restore. */
    identityId: string
    tenantId?: string
  }
}
