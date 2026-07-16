import type { Events } from '~/core/events'
import type { Provider, Providers } from '~/core/provider'
import type { MfaFacet } from '~/providers/mfa'
import type { PasswordsImpl } from '~/providers/passwords'
import type { Identities, IdentitiesImpl } from '../identities'
import type { Sessions, SessionsImpl } from '../sessions'
import type { Transport } from '../transport'

export namespace Flows {
  /** Internal dependency bag passed to flow sub-functions. Not part of the public API. */
  export interface Deps<Profile extends Identities.ProfileMetadataBase> {
    sessions: SessionsImpl
    identities: IdentitiesImpl<Profile>
    providers: Providers<Profile>
    transport: Transport.ITransport
    events: Events.IBus
    ctxFactory: (tenantId?: string) => Provider.Context<Profile>
    /** Lazy accessor — resolves the password facet at call-time; throws if the provider is absent. */
    requirePasswords: () => PasswordsImpl
    /** Lazy accessor — resolves the mfa facet at call-time; throws if the provider is absent. */
    requireMfa: () => MfaFacet
    cfg: Flows.Cfg
  }

  export interface Cfg {
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
    session: Sessions.Me | null
    /** Plaintext SID the client uses to authenticate; empty when `session` is null. */
    sid: string
    /** Intents the framework adapter must execute on the response. */
    intents: Provider.Intent[]
  }

  export type StepUpRequirement = {
    /** Required AAL on the post-step-up session. Default 2. */
    aal?: Sessions.AAL
    /** Methods that satisfy the requirement (any-of). Default ['totp']. */
    methods?: Sessions.FactorMethod[]
    /** Recency window in ms - re-auth required if last factor older than this. */
    freshness?: number
  }

  export type StepUpOutcome =
    | { satisfied: true; session: Sessions.Me; sid: string; intents: Provider.Intent[] }
    | { satisfied: false; reason: 'mfa-required' | 'fresh-required'; methods: Sessions.FactorMethod[] }

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

  export type SignUpFlowState<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    /** Opaque flow id; surfaced to the framework adapter to put on a __Host-duck-signup cookie. */
    id: string
    /** Identity row created at email-collected stage (profile.emailVerified=false until verifyEmail). */
    identityId: string
    /** Required stages (ordered); apps configure per signup type (passkey-only, B2B, etc.). */
    required: Flows.SignUpStage[]
    /** Stages the user has already completed; library guarantees idempotent appends. */
    completed: Flows.SignUpStage[]
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
    session: Sessions.Me
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
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
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
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
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
