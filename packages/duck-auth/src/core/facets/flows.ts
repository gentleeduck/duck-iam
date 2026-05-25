import { AuthErrorObject } from '../errors'
import type { Events } from '../types/events'
import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'
import type { IdentitiesFacet } from './identities'
import type { MfaFacet } from './mfa'
import type { PasswordsFacet } from './passwords'
import type { ProvidersFacet } from './providers'
import type { SessionsFacet } from './sessions'

export interface FlowsFacetConfig {
  /** What `signIn` calls SessionsFacet.rotateOrCreate with by default. */
  signInPurpose: 'signin' | 're-auth'
}

export const DEFAULT_FLOWS_CONFIG: FlowsFacetConfig = {
  signInPurpose: 'signin',
}

export interface SignInOptions {
  providerId: string
  input: unknown
  /** Currently-active SID (cookie or bearer); used by rotateOrCreate to revoke. */
  previousSid?: string
  ip?: string
  userAgent?: string
  tenantId?: string
}

export interface SignInOutcome {
  /** Persisted session row; `session.id` is the **hashed** row key. */
  session: Session.ISession
  /** Plaintext SID the client uses to authenticate (already on the response via intents). */
  sid: string
  /** Intents the framework adapter must execute on the response. */
  intents: Provider.Intent[]
}

/**
 * Flows facet — high-level orchestrations on top of sessions/identities/providers.
 * The single responsibility is wiring: providers return Intents, flows interpret
 * the lifecycle-affecting ones (startSession / requireMfa), the rest are passed
 * straight through to the framework adapter for HTTP execution.
 */
export interface StepUpRequirement {
  /** Required AAL on the post-step-up session. Default 2. */
  aal?: Session.AAL
  /** Methods that satisfy the requirement (any-of). Default ['totp']. */
  methods?: Session.FactorMethod[]
  /** Recency window in ms — re-auth required if last factor older than this. */
  freshness?: number
}

export type StepUpOutcome =
  | { satisfied: true; session: Session.ISession; sid: string; intents: Provider.Intent[] }
  | { satisfied: false; reason: 'mfa-required' | 'fresh-required'; methods: Session.FactorMethod[] }

export interface PasswordResetRequestInput {
  email: string
  /** Channel to use; default 'email'. */
  channel?: 'email' | 'sms' | 'webpush'
  /** Path on the app that handles the reset; library appends `?token=`. */
  callbackPath?: string
  /** Optional override; default 30 minutes. */
  ttlMs?: number
}

export interface PasswordResetCompleteInput {
  token: string
  newPassword: string
}

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
    private readonly _cfg: FlowsFacetConfig = DEFAULT_FLOWS_CONFIG,
  ) {}

  /**
   * Dispatch a sign-in via the named provider. Provider returns Intents;
   * the `startSession` intent is interpreted here (rotateOrCreate +
   * Transport.issue); other intents flow through to the caller.
   */
  async signIn(opts: SignInOptions): Promise<SignInOutcome> {
    if (!this._providers.has(opts.providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: opts.providerId,
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
      return { session: null as unknown as Session.ISession, sid: '', intents }
    }

    const identity = await this._identities.getById(
      startIntent.identityId,
      opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
    )
    if (!identity) {
      throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    }

    const { session, sid } = await this._sessions.rotateOrCreate({
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

    const transportIntents = this._transport.issue(sid, session, { fresh: true, absolute: false })
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
    if (!this._providers.has(providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId,
        detail: 'unknown provider id',
      })
    }
    return this._providers.begin(providerId, this._ctxFactory(opts.tenantId), input)
  }

  /** Revoke the current session and emit Transport.revoke intents. */
  async signOut(sid: string): Promise<{ intents: Provider.Intent[] }> {
    // revoke() is a no-op when the SID doesn't exist; safe to call unconditionally.
    await this._sessions.revoke(sid)
    return { intents: this._transport.revoke() }
  }

  // --- Step-up flow (DESIGN §6) -----------------------------------------

  /**
   * Check whether the current session satisfies a step-up requirement.
   * Returns `{satisfied: true}` (no-op) when the session already meets it;
   * otherwise returns a challenge enumerating the satisfying methods.
   */
  async checkStepUp(session: Session.ISession, requirement: StepUpRequirement): Promise<StepUpOutcome> {
    const requiredAal: Session.AAL = requirement.aal ?? 2
    const methods = requirement.methods ?? ['totp']
    const freshness = requirement.freshness

    if (session.aal >= requiredAal && session.fresh) {
      // Recency check
      if (freshness !== undefined && Date.now() - session.rotatedAt > freshness) {
        return { satisfied: false, reason: 'fresh-required', methods }
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
    const resolved = await this._sessions.getBySid(opts.currentSid)
    if (!resolved || !resolved.identityId) {
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
    const { session, sid } = await this._sessions.rotateOrCreate({
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
    const intents = this._transport.issue(sid, session, { fresh: true, absolute: false })
    return { session, sid, intents }
  }

  // --- Password reset (DESIGN §33.1) ------------------------------------

  /**
   * Request a password reset. Always responds successfully (no enumeration);
   * if the identity exists, a single-use token is minted, hashed at rest,
   * and dispatched via the configured channel as a reset link.
   *
   * `channels` and `findIdentityByEmail` are passed in because the recovery
   * flow doesn't know which app-side wiring drives email lookup or message
   * delivery — depending on a magic-link provider would couple this facet to
   * one provider's options.
   */
  async requestPasswordReset(opts: {
    input: PasswordResetRequestInput
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').Channel.IChannel>>
    tenantId?: string
  }): Promise<{ ok: true }> {
    const { email } = opts.input
    const channelKind = opts.input.channel ?? 'email'
    const ttlMs = opts.input.ttlMs ?? 30 * 60 * 1000
    const callbackPath = opts.input.callbackPath ?? '/auth/reset-password'
    const ctx = this._ctxFactory(opts.tenantId)

    // Rate limit per email and per IP (caller can inject extra dims via Limiter config).
    const limited = await ctx.limiter.consume(`recovery:password:${email.toLowerCase()}`)
    if (!limited.ok) {
      throw new AuthErrorObject('AUTH/RATE_LIMITED', {
        retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
      })
    }

    const identity = await opts.findIdentityByEmail(email, opts.tenantId)
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
    await channel.send({
      identity: identityRow,
      templateId: 'password-reset',
      vars: { url, ttlMin: Math.round(ttlMs / 60_000), requiresMfa: await this._mfa.hasTotp(identity.id, ctx.tenant) },
      tenant: ctx.tenant,
    })
    await this._events.emit('recovery.password.requested', { identityId: identity.id })
    return { ok: true }
  }

  /**
   * Complete a password reset by verifying the single-use token, setting
   * the new password, and revoking every other session for the identity.
   * If MFA is enrolled, callers must satisfy a step-up *before* hitting this
   * endpoint — the library refuses to swap passwords for accounts with MFA
   * unless a fresh AAL=2 session is passed via `currentSid`.
   */
  async completePasswordReset(
    input: PasswordResetCompleteInput & { currentSid?: string; tenantId?: string },
  ): Promise<{ ok: true }> {
    const { token, newPassword } = input
    if (typeof token !== 'string' || token.length === 0) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const ctx = this._ctxFactory(input.tenantId)
    const hash = ctx.crypto.sha256(token)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    const now = Date.now()
    if (!row || row.revokedAt) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    if (row.expiresAt !== undefined && row.expiresAt < now) {
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

    await ctx.stores.credentials.revoke(row.id, ctx.tenant)
    await this._passwords.set(row.identityId, newPassword, ctx.tenant)
    await this._sessions.revokeAllForIdentity(row.identityId)
    await this._events.emit('recovery.password.completed', { identityId: row.identityId })
    return { ok: true }
  }
}
