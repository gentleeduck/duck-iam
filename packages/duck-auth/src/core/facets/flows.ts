import { AuthErrorObject } from '../errors'
import type { AuthEvents } from '../types/events'
import type { AuthProvider } from '../types/provider'
import type { AuthSession } from '../types/session'
import type { AuthTransport } from '../types/transport'
import {
  cancelAccountDeletion as cancelAccountDeletionImpl,
  completeAccountDeletion as completeAccountDeletionImpl,
  requestAccountDeletion as requestAccountDeletionImpl,
} from './flows/account-deletion'
import {
  completeEmailVerification as completeEmailVerificationImpl,
  requestEmailVerification as requestEmailVerificationImpl,
} from './flows/email-verification'
import { impersonate as impersonateImpl, releaseImpersonation as releaseImpersonationImpl } from './flows/impersonate'
import {
  completePasswordReset as completePasswordResetImpl,
  requestPasswordReset as requestPasswordResetImpl,
} from './flows/password-reset'
import { linkProvider as linkProviderImpl, unlinkProvider as unlinkProviderImpl } from './flows/provider-link'
import {
  advanceSignUp as advanceSignUpImpl,
  beginSignUp as beginSignUpImpl,
  completeSignUp as completeSignUpImpl,
  getSignUpFlow as getSignUpFlowImpl,
} from './flows/signup'
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
    readonly _sessions: SessionsFacet,
    readonly _identities: IdentitiesFacet<Profile>,
    readonly _providers: ProvidersFacet<Profile>,
    readonly _transport: AuthTransport.ITransport,
    readonly _events: AuthEvents.IBus,
    readonly _ctxFactory: (tenantId?: string) => AuthProvider.IContext<Profile>,
    readonly _passwords: PasswordsFacet,
    readonly _mfa: MfaFacet,
    readonly _cfg: FlowsFacet.IConfig = DEFAULT_FLOWS_CONFIG,
  ) {}

  /**
   * Dispatch a sign-in via the named provider. AuthProvider returns Intents;
   * the `startSession` intent is interpreted here (rotateOrCreate +
   * AuthTransport.issue); other intents flow through to the caller.
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
      (i): i is Extract<AuthProvider.Intent, { type: 'startSession' }> => i.type === 'startSession',
    )
    if (!startIntent) {
      // AuthProvider completed without issuing a session (likely a requireMfa). Pass through.
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
  ): Promise<AuthProvider.Intent[]> {
    if (!isProviderIdSafe(providerId) || !this._providers.has(providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: isProviderIdSafe(providerId) ? providerId : 'invalid',
        detail: 'unknown provider id',
      })
    }
    return this._providers.begin(providerId, this._ctxFactory(opts.tenantId), input)
  }

  /** Revoke the current session and emit AuthTransport.revoke intents. */
  async signOut(sid: string): Promise<{ intents: AuthProvider.Intent[] }> {
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
    session: AuthSession.ISession,
    requirement: FlowsFacet.IStepUpRequirement,
  ): Promise<FlowsFacet.IStepUpOutcome> {
    const requiredAal: AuthSession.AAL = requirement.aal ?? 2
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
  }): Promise<{ session: AuthSession.ISession; sid: string; intents: AuthProvider.Intent[] }> {
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
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').AuthChannel.IChannel>>
    tenantId?: string
  }): Promise<{ ok: true }> {
    return requestPasswordResetImpl(this, opts)
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
    return completePasswordResetImpl(this, input)
  }

  // --- Email verification ---------------------------------------------------

  /**
   * Mint + dispatch an email-verification token. Idempotent under the
   * rate-limit window: callers can re-trigger from a "didn't get the
   * email" button without flooding the channel.
   *
   * Behavior:
   *   - Generates a 256-bit random token; persists sha-256 under
   *     AuthCredential.kind='recovery' with metadata.purpose='email-verification'
   *   - Per-identity rate limit at `verify:email:{identityId}` so
   *     resend pressure is bounded
   *   - No-op (returns { ok:true }) when the identity is already
   *     verified - avoids leaking "verified" status to the caller
   *   - Sends via the supplied channel with templateId='email-verification'
   */
  async requestEmailVerification(opts: FlowsFacet.IEmailVerificationRequestInput): Promise<{ ok: true }> {
    return requestEmailVerificationImpl(this, opts)
  }

  /**
   * Verify the supplied token, mark `identity.profile.emailVerified=true`,
   * consume the token. Returns `{ identityId }` on success.
   */
  async completeEmailVerification(input: FlowsFacet.IEmailVerificationCompleteInput): Promise<{ identityId: string }> {
    return completeEmailVerificationImpl(this, input)
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
    return requestAccountDeletionImpl(this, opts)
  }

  async completeAccountDeletion(
    input: FlowsFacet.IAccountDeletionCompleteInput,
  ): Promise<{ identityId: string; restorableUntil: number }> {
    return completeAccountDeletionImpl(this, input)
  }

  async cancelAccountDeletion(input: FlowsFacet.IAccountDeletionCancelInput): Promise<{ identityId: string }> {
    return cancelAccountDeletionImpl(this, input)
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
    return beginSignUpImpl(this, opts)
  }

  async getSignUpFlow(flowToken: string, tenantId?: string): Promise<FlowsFacet.ISignUpFlowState<Profile> | null> {
    return getSignUpFlowImpl(this, flowToken, tenantId)
  }

  async advanceSignUp(opts: {
    flowToken: string
    stage: FlowsFacet.ISignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  }): Promise<FlowsFacet.ISignUpFlowState<Profile>> {
    return advanceSignUpImpl(this, opts)
  }

  async completeSignUp(opts: {
    flowToken: string
    aal?: AuthSession.AAL
    factors?: AuthSession.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    previousSid?: string
  }): Promise<FlowsFacet.ISignInOutcome> {
    return completeSignUpImpl(this, opts)
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
      authorize: (realSession: AuthSession.ISession, targetIdentityId: string) => Promise<boolean>
    },
  ): Promise<FlowsFacet.IImpersonateOutcome> {
    return impersonateImpl(this, opts)
  }

  async linkProvider(opts: FlowsFacet.ILinkProviderInput): Promise<{ identityId: string; providerId: string }> {
    return linkProviderImpl(this, opts)
  }

  async unlinkProvider(opts: FlowsFacet.IUnlinkProviderInput): Promise<{ identityId: string; providerId: string }> {
    return unlinkProviderImpl(this, opts)
  }

  async releaseImpersonation(impersonationSid: string): Promise<{ intents: AuthProvider.Intent[] }> {
    return releaseImpersonationImpl(this, impersonationSid)
  }
}

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

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
    session: AuthSession.ISession | null
    /** Plaintext SID the client uses to authenticate; empty when `session` is null. */
    sid: string
    /** Intents the framework adapter must execute on the response. */
    intents: AuthProvider.Intent[]
  }

  export interface IStepUpRequirement {
    /** Required AAL on the post-step-up session. Default 2. */
    aal?: AuthSession.AAL
    /** Methods that satisfy the requirement (any-of). Default ['totp']. */
    methods?: AuthSession.FactorMethod[]
    /** Recency window in ms - re-auth required if last factor older than this. */
    freshness?: number
  }

  export type IStepUpOutcome =
    | { satisfied: true; session: AuthSession.ISession; sid: string; intents: AuthProvider.Intent[] }
    | { satisfied: false; reason: 'mfa-required' | 'fresh-required'; methods: AuthSession.FactorMethod[] }

  export interface IPasswordResetRequestInput {
    email: string
    /** AuthChannel to use; default 'email'. */
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
    /** AuthIdentity row created at email-collected stage (profile.emailVerified=false until verifyEmail). */
    identityId: string
    /** Required stages (ordered); apps configure per signup type (passkey-only, B2B, etc.). */
    required: FlowsFacet.ISignUpStage[]
    /** Stages the user has already completed; library guarantees idempotent appends. */
    completed: FlowsFacet.ISignUpStage[]
    /** Accumulated profile across stages; merged into AuthIdentity.profile at complete(). */
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
    /** AuthIdentity being impersonated. */
    targetIdentityId: string
    /** Human-readable reason; audit-logged via `identity.impersonated` event. */
    reason: string
    /** TTL cap; default 1 hour, cannot exceed 1 hour even if overridden. */
    ttlMs?: number
    tenantId?: string
  }

  export interface IImpersonateOutcome {
    session: AuthSession.ISession
    /** Plaintext SID for the new actingAs session (separate from real session). */
    sid: string
    intents: AuthProvider.Intent[]
  }

  export type ISignUpStage =
    | 'email-collected'
    | 'email-verified'
    | 'profile-completed'
    | 'mfa-enrolled'
    | 'terms-accepted'
    | 'completed'

  export interface ILinkProviderInput {
    /** AuthIdentity to attach the provider link to. */
    identityId: string
    /** AuthProvider id (`'authGoogle'`, `'authGithub'`, etc). */
    providerId: string
    /** AuthProvider-side subject id (verified by the OAuth dance the caller just completed). */
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
    /** AuthIdentity to verify. */
    identityId: string
    /** AuthChannel keyed by kind. Email is the typical default. */
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').AuthChannel.IChannel>>
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
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/channel').AuthChannel.IChannel>>
    /** AuthChannel kind to use; default `'email'`. */
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
    /** AuthIdentity to restore. */
    identityId: string
    tenantId?: string
  }
}
