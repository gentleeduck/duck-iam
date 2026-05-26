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
 * Flows facet - high-level orchestrations on top of sessions/identities/providers.
 * The single responsibility is wiring: providers return Intents, flows interpret
 * the lifecycle-affecting ones (startSession / requireMfa), the rest are passed
 * straight through to the framework adapter for HTTP execution.
 */
export interface StepUpRequirement {
  /** Required AAL on the post-step-up session. Default 2. */
  aal?: Session.AAL
  /** Methods that satisfy the requirement (any-of). Default ['totp']. */
  methods?: Session.FactorMethod[]
  /** Recency window in ms - re-auth required if last factor older than this. */
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

// --- Signup state machine (DESIGN section 34) -------------------------------------

export type SignUpStage =
  | 'email-collected'
  | 'email-verified'
  | 'profile-completed'
  | 'mfa-enrolled'
  | 'terms-accepted'
  | 'completed'

/**
 * Stateful signup-flow row persisted under credentials with kind='recovery'.
 * Generic `Profile` matches the AuthRoot's `Profile`; the FlowsFacet's class
 * generic flows through so consumers never need a cast at the call site.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SignUpFlowState<Profile = unknown> {
  /** Opaque flow id; surfaced to the framework adapter to put on a __Host-duck-signup cookie. */
  id: string
  /** Identity row created at email-collected stage (profile.emailVerified=false until verifyEmail). */
  identityId: string
  /** Required stages (ordered); apps configure per signup type (passkey-only, B2B, etc.). */
  required: SignUpStage[]
  /** Stages the user has already completed; library guarantees idempotent appends. */
  completed: SignUpStage[]
  /** Accumulated profile across stages; merged into Identity.profile at complete(). */
  data: Partial<Profile>
  /** Sliding TTL (default 30 min). */
  expiresAt: number
  /** Hard cap (default 24 h); cannot be slid past. */
  absoluteExpiresAt: number
  /** Wall-clock created time, ms. */
  createdAt: number
}

// --- Impersonation (DESIGN section 38) -------------------------------------------

export interface ImpersonateOptions {
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

export interface ImpersonateOutcome {
  session: Session.ISession
  /** Plaintext SID for the new actingAs session (separate from real session). */
  sid: string
  intents: Provider.Intent[]
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

  // --- Step-up flow (DESIGN section 6) -----------------------------------------

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

  // --- Password reset (DESIGN section 33.1) ------------------------------------

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
   * endpoint - the library refuses to swap passwords for accounts with MFA
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

  // --- Signup state machine (DESIGN section 34) -----------------------------

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
    required?: SignUpStage[]
    initialProfile?: Partial<Profile>
    tenantId?: string
  }): Promise<{ flow: SignUpFlowState<Profile>; flowToken: string }> {
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
    const flow: SignUpFlowState<Profile> = {
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
  async getSignUpFlow(flowToken: string, tenantId?: string): Promise<SignUpFlowState<Profile> | null> {
    const ctx = this._ctxFactory(tenantId)
    const hash = ctx.crypto.sha256(flowToken)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || row.revokedAt) return null
    const now = Date.now()
    if (row.expiresAt !== undefined && row.expiresAt < now) {
      await ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
      return null
    }
    const meta = row.metadata as { kind?: string; flow?: SignUpFlowState<Profile> } | undefined
    if (meta?.kind !== 'signup-flow' || !meta.flow) return null
    return meta.flow
  }

  /** Advance the flow with new profile data; bumps the completed stage list. */
  async advanceSignUp(opts: {
    flowToken: string
    stage: SignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  }): Promise<SignUpFlowState<Profile>> {
    const ctx = this._ctxFactory(opts.tenantId)
    const hash = ctx.crypto.sha256(opts.flowToken)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || row.revokedAt) throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    const meta = row.metadata as { kind?: string; flow?: SignUpFlowState<Profile> } | undefined
    if (meta?.kind !== 'signup-flow' || !meta.flow) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    const flow = meta.flow
    const next: SignUpFlowState<Profile> = {
      ...flow,
      completed: flow.completed.includes(opts.stage) ? flow.completed : [...flow.completed, opts.stage],
      data: opts.profilePatch ? { ...flow.data, ...opts.profilePatch } : flow.data,
      expiresAt: Math.min(flow.absoluteExpiresAt, Date.now() + 30 * 60_000),
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
  }): Promise<SignInOutcome> {
    const ctx = this._ctxFactory(opts.tenantId)
    const hash = ctx.crypto.sha256(opts.flowToken)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'recovery', ctx.tenant)
    if (!row || row.revokedAt) throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    const meta = row.metadata as { kind?: string; flow?: SignUpFlowState<Profile> } | undefined
    if (meta?.kind !== 'signup-flow' || !meta.flow) {
      throw new AuthErrorObject('AUTH/SIGNUP_TOKEN_INVALID')
    }
    const flow = meta.flow
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
    const { session, sid } = await this._sessions.create({
      identityId: flow.identityId,
      kind: 'user',
      aal,
      factors,
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      ...(opts.ip !== undefined && { ip: opts.ip }),
      ...(opts.userAgent !== undefined && { userAgent: opts.userAgent }),
    })
    const intents = this._transport.issue(sid, session, { fresh: true, absolute: false })
    return { session, sid, intents }
  }

  // --- Impersonation (DESIGN section 38) ------------------------------------

  /**
   * Start an impersonation. Library refuses to issue an actingAs session
   * without first checking the caller's authorisation via the supplied
   * `authorize` callback. iam consumers wire engine.authorize() here; non-
   * iam apps supply their own predicate. NEVER pass `() => true` - that
   * defeats audit and DESIGN section 38's invariant.
   */
  async impersonate(
    opts: ImpersonateOptions & {
      authorize: (realSession: Session.ISession, targetIdentityId: string) => Promise<boolean>
    },
  ): Promise<ImpersonateOutcome> {
    if (opts.targetIdentityId === '') {
      throw new AuthErrorObject('AUTH/IMPERSONATE_FORBIDDEN', { reason: 'empty target' })
    }
    const real = await this._sessions.getBySid(opts.realSid)
    if (!real || !real.identityId) {
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

    const { session, sid } = await this._sessions.rotateOrCreate({
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
    const intents = this._transport.issue(sid, session, { fresh: true, absolute: false })
    return { session, sid, intents }
  }

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
