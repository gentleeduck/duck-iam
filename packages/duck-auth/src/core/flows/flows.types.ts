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

  export type LinkProviderInput<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    /** Identity to attach the provider link to. */
    identityId: string
    /** Provider id (`'authGoogle'`, `'authGithub'`, etc). */
    providerId: string
    /** Provider-side subject id (verified by the oauth dance the caller just completed). */
    providerSub: string
    /**
     * Mandatory. Answers the one question the library cannot: did the caller
     * actually complete this provider's dance for this subject?
     *
     * `providerSub` arrives as a plain string. Nothing about it is verifiable
     * from inside duck-auth - it is whatever the host passed - and a link is a
     * permanent authentication factor. Wire it to a route that trusts a request
     * body and an attacker links their own Google account to a victim's identity
     * and signs in as them from then on; wire it to a completed OAuth callback
     * and it is exactly right. Nothing in the signature tells those two apart.
     *
     * The callback is where the host states which one it is. It receives the
     * identity being modified and the link about to be written; answer `false`
     * unless the `providerSub` came from a token exchange your code performed.
     * Never `async () => true` - that is the same hole with a callback in front
     * of it, and `impersonate`'s `authorize` carries the same warning for the
     * same reason.
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
    /**
     * Where to send the undo link, if the library should send it. Omit and the
     * `cancellationToken` comes back in the result for the host to deliver (or
     * to drop, which is how you turn undo off - nobody else ever holds the
     * plaintext).
     */
    channels?: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
    /** Channel kind to use when `channels` is given; default `'email'`. */
    channel?: 'email' | 'sms' | 'webpush'
    /** Path on the app that handles the undo. Default `/auth/cancel-deletion`. */
    callbackPath?: string
    tenantId?: string
  }

  /**
   * Cancel by presenting the undo token `completeAccountDeletion` minted.
   *
   * The token names its own subject, so no `identityId` is passed and no
   * callback is consulted: holding the token IS the authorization, exactly as
   * holding the deletion token is authorization to delete. This is the branch a
   * user clicking "undo" in their mail takes - they have the token and no admin
   * rights at all.
   */
  export type AccountDeletionCancelByToken = {
    /** Single-use, expires when the grace window does. */
    token: string
    tenantId?: string
    identityId?: never
    authorize?: never
  }

  /**
   * Cancel on someone else's behalf, with no token in hand - an operator
   * restoring an account from a support queue.
   */
  export type AccountDeletionCancelByAuthorize = {
    /** Identity to restore. */
    identityId: string
    /**
     * Mandatory on this branch, and the only gate on it - a cancel restores an
     * account from an id alone.
     *
     * Required rather than optional on purpose: every sibling in this flow is
     * gated (`completeAccountDeletion` by a single-use token, `impersonate` by
     * a callback of exactly this shape), and there is no default the library
     * could pick that is safe. Only the host knows who is asking.
     *
     * The identity is soft-deleted at this point, so it cannot be loaded and
     * handed over - the id is what you get. Resolve the caller from your own
     * request context and answer for that.
     */
    authorize: (identityId: string) => Promise<boolean>
    tenantId?: string
    token?: never
  }

  /**
   * One of the two, never both and never neither. Supplying both is refused
   * rather than resolved in favour of one: which gate applied would depend on a precedence rule
   * nobody reading the call site can see.
   */
  export type AccountDeletionCancelInput = AccountDeletionCancelByToken | AccountDeletionCancelByAuthorize
}
