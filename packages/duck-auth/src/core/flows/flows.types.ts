import type { Events } from '~/core/events'
import type { Provider, Providers } from '~/core/provider'
import type { MfaFacet } from '~/providers/mfa'
import type { PasswordsImpl } from '~/providers/passwords'
import type { Identities, IdentitiesImpl } from '../identities'
import type { Sessions, SessionsImpl } from '../sessions'
import type { Transport } from '../transport'

/** Inputs and results for the sign-in, sign-up, link, step-up and recovery flows. */
export namespace Flows {
  /** Internal dependency bag passed to flow sub-functions. Not part of the public API. */
  export interface Deps<Profile extends Identities.ProfileMetadataBase> {
    sessions: SessionsImpl
    identities: IdentitiesImpl<Profile>
    providers: Providers<Profile>
    transport: Transport.ITransport
    events: Events.IBus
    ctxFactory: (tenantId?: string) => Provider.Context<Profile>
    /** Resolves the password facet at call time, throwing when the provider is absent. */
    requirePasswords: () => PasswordsImpl
    /** Resolves the mfa facet at call time, throwing when the provider is absent. */
    requireMfa: () => MfaFacet
    cfg: Flows.Cfg
  }

  export interface Cfg {
    /** What `signIn` calls `SessionsImpl.rotateOrCreate` with by default. */
    signInPurpose: 'signin' | 're-auth'
  }

  export interface SignInOptions {
    providerId: string
    input: unknown
    /** The active SID, from the cookie or the bearer; `rotateOrCreate` revokes it. */
    previousSid?: string
    ip?: string
    userAgent?: string
    tenantId?: string
  }

  export type SignInOutcome = {
    /** Persisted session row, keyed by the hashed sid. Null when the provider issued no `startSession`
     *  intent and wants the caller to answer with something else - a redirect or a json body it put in
     *  `intents`; `sid` is then empty too. A `requireMfa` intent does not land here: it throws
     *  `AUTH_STEP_UP_REQUIRED`. */
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
    /** Recency window in ms; a last factor older than this needs re-auth. */
    freshness?: number
  }

  export type StepUpOutcome =
    | { satisfied: true; session: Sessions.Me; sid: string; intents: Provider.Intent[] }
    | { satisfied: false; reason: 'mfa-required' | 'fresh-required'; methods: Sessions.FactorMethod[] }

  export type PasswordResetRequestInput = {
    email: string
    /** Default 'email'. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Path on the app that handles the reset; the library appends `?token=`. */
    callbackPath?: string
    /** Default 30 minutes. */
    ttlMs?: number
  }

  export type PasswordResetCompleteInput = {
    token: string
    newPassword: string
  }

  export type SignUpFlowState<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    /** Opaque flow id; surfaced to the framework adapter to put on a __Host-duck-signup cookie. */
    id: string
    /** Created at the email-collected stage, with `emailVerified` false until `completeEmailVerification`. */
    identityId: string
    /** Ordered, and configured per signup type: passkey-only, B2B and the rest. */
    required: Flows.SignUpStage[]
    /** Appends are idempotent. */
    completed: Flows.SignUpStage[]
    /** Accumulated across stages, merged into `Identity.profile` at `complete()`. */
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
    /** Audit-logged on the `identity.impersonated` event. */
    reason: string
    /** Which IAM decision authorised this, audit-logged beside `reason`. The event has always declared
     *  the field and nothing could supply it, so every impersonation was untraceable to an authorization. */
    iamDecisionId?: string
    /** One hour, and an override cannot raise it. */
    ttlMs?: number
    tenantId?: string
  }

  export type ImpersonateOutcome = {
    session: Sessions.Me
    /** For the new `actingAs` session, separate from the real one. */
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

  export type LinkProviderInput<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    /** Identity to attach the provider link to. */
    identityId: string
    /** Such as `'authGoogle'` or `'authGithub'`. */
    providerId: string
    /** Verified by the oauth dance the caller just completed. */
    providerSub: string
    /**
     * SECURITY: mandatory, and the only thing standing between this call and an account takeover. `providerSub`
     * is whatever the host passed and a link is a permanent authentication factor, so wiring this to a route
     * that trusts a request body lets an attacker link their own Google account to a victim and sign in as them.
     * Answer `false` unless the `providerSub` came from a token exchange your own code performed, and never
     * `async () => true`.
     */
    authorize: (input: {
      identity: Identities.Me<Profile>
      providerId: string
      providerSub: string
    }) => Promise<boolean>
    /** Tenant scope. */
    tenantId?: string
  }

  export type UnlinkProviderInput = {
    identityId: string
    providerId: string
    tenantId?: string
    /** Bypasses the "would lock out the user" guard. For account deletion and admin overrides only. */
    allowLockout?: boolean
  }

  export type EmailVerificationRequestInput = {
    /** Identity to verify. */
    identityId: string
    /** Keyed by kind. */
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
    /** Default 'email'. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Default 30 minutes. */
    ttlMs?: number
    /** The library appends `?token=`. Default `/auth/verify-email`. */
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
    /** One channel per delivery method; the request goes out over each one named. */
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
    /** Default `'email'`. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Default 30 minutes. */
    ttlMs?: number
    /** Path on the app that handles the confirmation. Default `/auth/delete-account`. */
    callbackPath?: string
    /** Persisted in metadata and surfaced in the audit log. */
    reason?: string
    tenantId?: string
  }

  export type AccountDeletionCompleteInput = {
    /** Token from the confirmation link. */
    token: string
    /** Where to send the undo link, when the library is to send it. Omit it and `cancellationToken` comes
     *  back in the result for the host to deliver, or to drop, which is how undo is turned off. */
    channels?: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
    /** Used when `channels` is given. Default `'email'`. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Path on the app that handles the undo. Default `/auth/cancel-deletion`. */
    callbackPath?: string
    tenantId?: string
  }

  /** Cancel by presenting the undo token `completeAccountDeletion` minted. The token names its own subject,
   *  so holding it is the authorization and no callback is consulted: this is the branch a user clicking
   *  "undo" in their mail takes, with no admin rights at all. */
  export type AccountDeletionCancelByToken = {
    /** Single-use, expires when the grace window does. */
    token: string
    tenantId?: string
    identityId?: never
    authorize?: never
  }

  /** Cancel on someone else's behalf with no token in hand, the way an operator restores an account from
   *  a support queue. */
  export type AccountDeletionCancelByAuthorize = {
    /** Identity to restore. */
    identityId: string
    /** SECURITY: mandatory, and the only gate on this branch, where a cancel restores an account from an id
     *  alone. The identity is soft-deleted here so it cannot be loaded and handed over; resolve the caller
     *  from your own request context and answer for that. */
    authorize: (identityId: string) => Promise<boolean>
    tenantId?: string
    token?: never
  }

  /** One of the two, never both and never neither. Supplying both is refused rather than resolved, because which
   *  gate applied would then turn on a precedence rule nobody reading the call site can see. */
  export type AccountDeletionCancelInput = AccountDeletionCancelByToken | AccountDeletionCancelByAuthorize
}
