import type { ProvidersFacet } from '~/core/provider/provider.facet'
import type { MfaFacet } from '~/providers/mfa/mfa.facet'
import type { PasswordsFacet } from '~/providers/password/password.facet'
import { AuthError } from '../errors'
import type { IdentitiesFacet } from '../identities/identities.facet'
import type { Provider } from '../provider/provider.types'
import type { SessionsFacet } from '../sessions/sessions.facet'
import type { Session } from '../sessions/sessions.types'
import type { Identity } from '../types'
import type { Events } from '../types/provider'
import type { Transport } from '../types/session'
import {
  cancelAccountDeletion as cancelAccountDeletionImpl,
  completeAccountDeletion as completeAccountDeletionImpl,
  requestAccountDeletion as requestAccountDeletionImpl,
} from './flows/account-deletion.flow'
import {
  completeEmailVerification as completeEmailVerificationImpl,
  requestEmailVerification as requestEmailVerificationImpl,
} from './flows/email-verification.flow'
import {
  impersonate as impersonateImpl,
  releaseImpersonation as releaseImpersonationImpl,
} from './flows/impersonate.flow'
import {
  completePasswordReset as completePasswordResetImpl,
  requestPasswordReset as requestPasswordResetImpl,
} from './flows/password-reset.flow'
import { linkProvider as linkProviderImpl, unlinkProvider as unlinkProviderImpl } from './flows/provider-link.flow'
import {
  advanceSignUp as advanceSignUpImpl,
  beginSignUp as beginSignUpImpl,
  completeSignUp as completeSignUpImpl,
  getSignUpFlow as getSignUpFlowImpl,
} from './flows/signup.flow'

export namespace FlowsFacet {
  /** Internal dependency bag passed to flow sub-functions. Not part of the public API. */
  export interface Deps<Profile extends Identity.ProfileMetadataBase> {
    sessions: SessionsFacet
    identities: IdentitiesFacet<Profile>
    providers: ProvidersFacet<Profile>
    transport: Transport.ITransport
    events: Events.IBus
    ctxFactory: (tenantId?: string) => Provider.Context<Profile>
    /** Lazy accessor — resolves the password facet at call-time; throws if the provider is absent. */
    requirePasswords: () => PasswordsFacet
    /** Lazy accessor — resolves the mfa facet at call-time; throws if the provider is absent. */
    requireMfa: () => MfaFacet
    cfg: FlowsFacet.Config
  }

  export interface Config {
    /** What `signIn` calls SessionsFacet.rotateOrCreate with by default. */
    signInPurpose: 'signin' | 're-auth'
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

  export type SignInOutcome = {
    /**
     * Persisted session row; `session.id` is the **hashed** row key. Null when
     * the provider issued no `startSession` intent (typically because it
     * returned `requireMfa` and the caller is mid-flow); in that case `sid`
     * is also empty and `intents` carries the provider's response.
     */
    session: Session.Me | null
    /** Plaintext SID the client uses to authenticate; empty when `session` is null. */
    sid: string
    /** Intents the framework adapter must execute on the response. */
    intents: Provider.Intent[]
  }

  export type StepUpRequirement = {
    /** Required AAL on the post-step-up session. Default 2. */
    aal?: Session.AAL
    /** Methods that satisfy the requirement (any-of). Default ['totp']. */
    methods?: Session.FactorMethod[]
    /** Recency window in ms - re-auth required if last factor older than this. */
    freshness?: number
  }

  export type StepUpOutcome =
    | { satisfied: true; session: Session.Me; sid: string; intents: Provider.Intent[] }
    | { satisfied: false; reason: 'mfa-required' | 'fresh-required'; methods: Session.FactorMethod[] }

  export type PasswordResetRequestInput = {
    email: string
    /** Channel to use; default 'email'. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Path on the app that handles the reset; library appends `?token=`. */
    callbackPath?: string
    /** Optional override; default 30 minutes. */
    ttlMs?: number
  }

  export type PasswordResetCompleteInput = {
    token: string
    newPassword: string
  }

  export type SignUpFlowState<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> = {
    /** Opaque flow id; surfaced to the framework adapter to put on a __Host-duck-signup cookie. */
    id: string
    /** Identity row created at email-collected stage (profile.emailVerified=false until verifyEmail). */
    identityId: string
    /** Required stages (ordered); apps configure per signup type (passkey-only, B2B, etc.). */
    required: FlowsFacet.SignUpStage[]
    /** Stages the user has already completed; library guarantees idempotent appends. */
    completed: FlowsFacet.SignUpStage[]
    /** Accumulated profile across stages; merged into Identity.profile at complete(). */
    data: Partial<Profile>
    /** Sliding TTL (default 30 min). */
    expiresAt: number
    /** Hard cap (default 24 h); cannot be slid past. */
    absoluteExpiresAt: number
    /** Wall-clock created time, ms. */
    createdAt: number
  }

  export type ImpersonateOptions = {
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

  export type ImpersonateOutcome = {
    session: Session.Me
    /** Plaintext SID for the new actingAs session (separate from real session). */
    sid: string
    intents: Provider.Intent[]
  }

  export type SignUpStage =
    | 'email-collected'
    | 'email-verified'
    | 'profile-completed'
    | 'mfa-enrolled'
    | 'terms-accepted'
    | 'completed'

  export type LinkProviderInput = {
    /** Identity to attach the provider link to. */
    identityId: string
    /** Provider id (`'authGoogle'`, `'authGithub'`, etc). */
    providerId: string
    /** Provider-side subject id (verified by the oauth dance the caller just completed). */
    providerSub: string
    /** Tenant scope. */
    tenantId?: string
  }

  export type UnlinkProviderInput = {
    identityId: string
    providerId: string
    tenantId?: string
    /**
     * Set true to bypass the "would lock out the user" guard. Use only
     * during account deletion flows or admin overrides.
     */
    allowLockout?: boolean
  }

  export type EmailVerificationRequestInput = {
    /** Identity to verify. */
    identityId: string
    /** Channel keyed by kind. Email is the typical default. */
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/infra').Channel.Channel>>
    /** Which channel to dispatch on; default 'email'. */
    channel?: 'email' | 'sms' | 'webpush'
    /** TTL of the verification token, ms. Default 30 minutes. */
    ttlMs?: number
    /** Callback path on the app; library appends `?token=`. Default `/auth/verify-email`. */
    callbackPath?: string
    tenantId?: string
  }

  export type EmailVerificationCompleteInput = {
    /** Token plaintext as received from the verify link. */
    token: string
    tenantId?: string
  }

  export type AccountDeletionRequestInput = {
    identityId: string
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/infra').Channel.Channel>>
    /** Channel kind to use; default `'email'`. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Token TTL in ms. Default 30 minutes. */
    ttlMs?: number
    /** Path on the app that handles the confirmation. Default `/AUTH/delete-account`. */
    callbackPath?: string
    /** Optional human-readable reason persisted in metadata; surfaces in audit log. */
    reason?: string
    tenantId?: string
  }

  export type AccountDeletionCompleteInput = {
    /** Token from the confirmation link. */
    token: string
    tenantId?: string
  }

  export type AccountDeletionCancelInput = {
    /** Identity to restore. */
    identityId: string
    tenantId?: string
  }
}

export const DEFAULT_FLOWS_CONFIG: FlowsFacet.Config = {
  signInPurpose: 'signin',
}

export class FlowsFacet<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> {
  private readonly _deps: FlowsFacet.Deps<Profile>

  constructor(
    sessions: SessionsFacet,
    identities: IdentitiesFacet<Profile>,
    providers: ProvidersFacet<Profile>,
    transport: Transport.ITransport,
    events: Events.IBus,
    ctxFactory: (tenantId?: string) => Provider.Context<Profile>,
    requirePasswords: () => PasswordsFacet,
    requireMfa: () => MfaFacet,
    cfg: FlowsFacet.Config = DEFAULT_FLOWS_CONFIG,
  ) {
    this._deps = { sessions, identities, providers, transport, events, ctxFactory, requirePasswords, requireMfa, cfg }
  }

  /** Expose deps for testing extracted flow functions directly. */
  get deps(): FlowsFacet.Deps<Profile> {
    return this._deps
  }

  /**
   * Dispatch a sign-in via the named provider. Provider returns Intents;
   * the `startSession` intent is interpreted here (rotateOrCreate +
   * Transport.issue); other intents flow through to the caller.
   */
  async signIn(opts: FlowsFacet.SignInOptions): Promise<FlowsFacet.SignInOutcome> {
    const { sessions, identities, providers, transport, events, ctxFactory, cfg } = this._deps
    if (!isProviderIdSafe(opts.providerId) || !providers.has(opts.providerId)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: isProviderIdSafe(opts.providerId) ? opts.providerId : 'invalid',
        detail: 'unknown provider id',
      })
    }
    const ctx = ctxFactory(opts.tenantId)
    const rawIntents = await providers.complete(opts.providerId, ctx, opts.input)

    const startIntent = rawIntents.find(
      (i): i is Extract<Provider.InternalIntent, { type: 'startSession' }> => i.type === 'startSession',
    )
    if (!startIntent) {
      const adapterIntents = rawIntents.filter(
        (i): i is Provider.Intent => i.type !== 'startSession' && i.type !== 'requireMfa',
      )
      return { session: null, sid: '', intents: adapterIntents }
    }

    const identity = await identities.getById(
      startIntent.identityId,
      opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
    )
    if (!identity) {
      throw new AuthError('AUTH_UNAUTHENTICATED')
    }

    const { session, sid, csrfToken } = await sessions.rotateOrCreate({
      purpose: opts.previousSid ? 're-auth' : cfg.signInPurpose,
      ...(opts.previousSid !== undefined && { previousSid: opts.previousSid }),
      identityId: startIntent.identityId,
      kind: 'user',
      aal: startIntent.aal,
      factors: startIntent.factors,
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      ...(opts.ip !== undefined && { ip: opts.ip }),
      ...(opts.userAgent !== undefined && { userAgent: opts.userAgent }),
    })

    const transportIntents = transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
    await events.emit('signin.success', { identity, factors: startIntent.factors })
    return {
      session,
      sid,
      intents: [
        ...rawIntents.filter((i): i is Provider.Intent => i.type !== 'startSession' && i.type !== 'requireMfa'),
        ...transportIntents,
      ],
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
    const { providers, ctxFactory } = this._deps
    if (!isProviderIdSafe(providerId) || !providers.has(providerId)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: isProviderIdSafe(providerId) ? providerId : 'invalid',
        detail: 'unknown provider id',
      })
    }
    return providers.begin(providerId, ctxFactory(opts.tenantId), input)
  }

  /** Revoke the current session and emit Transport.revoke intents. */
  async signOut(sid: string): Promise<{ intents: Provider.Intent[] }> {
    const { sessions, transport } = this._deps
    // sessions.revoke() also typeof-guards, but defending here means a non-string
    // sid never reaches the bus + transport (revoke remains a no-op).
    if (typeof sid === 'string' && sid.length > 0 && sid.length <= 4096) {
      await sessions.revoke(sid)
    }
    return { intents: transport.revoke() }
  }

  // --- Step-up flow -----------------------------------------

  /**
   * Check whether the current session satisfies a step-up requirement.
   * Returns `{satisfied: true}` (no-op) when the session already meets it;
   * otherwise returns a challenge enumerating the satisfying methods.
   */
  async checkStepUp(session: Session.Me, requirement: FlowsFacet.StepUpRequirement): Promise<FlowsFacet.StepUpOutcome> {
    const requiredAal: Session.AAL = requirement.aal ?? 2
    const methods = requirement.methods ?? ['totp']
    const freshness = requirement.freshness

    if (session.aal >= requiredAal && session.fresh) {
      // Fail-closed: non-finite rotatedAt would slip the freshness gate.
      if (freshness !== undefined) {
        const rotatedAtMs =
          session.rotatedAt instanceof Date
            ? session.rotatedAt.getTime()
            : typeof session.rotatedAt === 'number' && Number.isFinite(session.rotatedAt)
              ? session.rotatedAt
              : Number.NaN
        if (!Number.isFinite(rotatedAtMs) || Date.now() - rotatedAtMs > freshness) {
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
  }): Promise<{ session: Session.Me; sid: string; intents: Provider.Intent[] }> {
    if (opts.method !== 'totp' && opts.method !== 'backup-code') {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    if (typeof opts.code !== 'string' || opts.code.length === 0 || opts.code.length > 64) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    const { sessions, requireMfa, transport } = this._deps
    const mfa = requireMfa()
    const resolved = await sessions.getBySid(opts.currentSid)
    if (!resolved?.identityId) {
      throw new AuthError('AUTH_UNAUTHENTICATED')
    }
    const ok =
      opts.method === 'totp'
        ? await mfa.verifyTotp(
            resolved.identityId,
            opts.code,
            opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
          )
        : await mfa.verifyBackupCode(
            resolved.identityId,
            opts.code,
            opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {},
          )
    if (!ok) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    const { session, sid, csrfToken } = await sessions.rotateOrCreate({
      purpose: 'step-up',
      previousSid: opts.currentSid,
      identityId: resolved.identityId,
      kind: resolved.kind,
      aal: 2,
      factors: [
        ...resolved.factors,
        { method: opts.method === 'totp' ? 'totp' : 'backup-code', completedAt: new Date() },
      ],
      ...(resolved.tenantId !== undefined && { tenantId: resolved.tenantId }),
    })
    const intents = transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
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
    input: FlowsFacet.PasswordResetRequestInput
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('../types/infra').Channel.Channel>>
    tenantId?: string
  }): Promise<{ ok: true }> {
    return requestPasswordResetImpl(this._deps, opts)
  }

  /**
   * Complete a password reset by verifying the single-use token, setting
   * the new password, and revoking every other session for the identity.
   * If MFA is enrolled, callers must satisfy a step-up *before* hitting this
   * endpoint - the library refuses to swap passwords for accounts with MFA
   * unless a fresh AAL=2 session is passed via `currentSid`.
   */
  async completePasswordReset(
    input: FlowsFacet.PasswordResetCompleteInput & { currentSid?: string; tenantId?: string },
  ): Promise<{ ok: true }> {
    return completePasswordResetImpl(this._deps, input)
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
  async requestEmailVerification(opts: FlowsFacet.EmailVerificationRequestInput): Promise<{ ok: true }> {
    return requestEmailVerificationImpl(this._deps, opts)
  }

  /**
   * Verify the supplied token, mark `identity.profile.emailVerified=true`,
   * consume the token. Returns `{ identityId }` on success.
   */
  async completeEmailVerification(input: FlowsFacet.EmailVerificationCompleteInput): Promise<{ identityId: string }> {
    return completeEmailVerificationImpl(this._deps, input)
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
  async requestAccountDeletion(opts: FlowsFacet.AccountDeletionRequestInput): Promise<{ ok: true }> {
    return requestAccountDeletionImpl(this._deps, opts)
  }

  async completeAccountDeletion(
    input: FlowsFacet.AccountDeletionCompleteInput,
  ): Promise<{ identityId: string; restorableUntil: number }> {
    return completeAccountDeletionImpl(this._deps, input)
  }

  async cancelAccountDeletion(input: FlowsFacet.AccountDeletionCancelInput): Promise<{ identityId: string }> {
    return cancelAccountDeletionImpl(this._deps, input)
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
    required?: FlowsFacet.SignUpStage[]
    initialProfile?: Partial<Profile>
    tenantId?: string
  }): Promise<{ flow: FlowsFacet.SignUpFlowState<Profile>; flowToken: string }> {
    return beginSignUpImpl(this._deps, opts)
  }

  async getSignUpFlow(flowToken: string, tenantId?: string): Promise<FlowsFacet.SignUpFlowState<Profile> | null> {
    return getSignUpFlowImpl(this._deps, flowToken, tenantId)
  }

  async advanceSignUp(opts: {
    flowToken: string
    stage: FlowsFacet.SignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  }): Promise<FlowsFacet.SignUpFlowState<Profile>> {
    return advanceSignUpImpl(this._deps, opts)
  }

  async completeSignUp(opts: {
    flowToken: string
    aal?: Session.AAL
    factors?: Session.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    previousSid?: string
  }): Promise<FlowsFacet.SignInOutcome> {
    return completeSignUpImpl(this._deps, opts)
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
    opts: FlowsFacet.ImpersonateOptions & {
      authorize: (realSession: Session.Me, targetIdentityId: string) => Promise<boolean>
    },
  ): Promise<FlowsFacet.ImpersonateOutcome> {
    return impersonateImpl(this._deps, opts)
  }

  async linkProvider(opts: FlowsFacet.LinkProviderInput): Promise<{ identityId: string; providerId: string }> {
    return linkProviderImpl(this._deps, opts)
  }

  async unlinkProvider(opts: FlowsFacet.UnlinkProviderInput): Promise<{ identityId: string; providerId: string }> {
    return unlinkProviderImpl(this._deps, opts)
  }

  async releaseImpersonation(impersonationSid: string): Promise<{ intents: Provider.Intent[] }> {
    return releaseImpersonationImpl(this._deps, impersonationSid)
  }
}

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}
