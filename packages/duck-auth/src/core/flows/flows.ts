import type { Events } from '~/core/events'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Providers } from '~/core/provider'
import type { MfaFacet } from '~/providers/mfa'
import type { PasswordsImpl } from '~/providers/passwords'
import { type Answer, answer } from '../answer'
import { AuthError } from '../errors'
import type { Identities, IdentitiesImpl } from '../identities'
import type { Provider } from '../provider'
import { canonicalProviderId, echoableProviderId } from '../provider/provider.constants'
import type { Sessions, SessionsImpl } from '../sessions'
import type { TenantContext } from '../tenant/tenant.types'
import type { Transport } from '../transport'
import {
  cancelAccountDeletion as cancelAccountDeletionImpl,
  completeAccountDeletion as completeAccountDeletionImpl,
  requestAccountDeletion as requestAccountDeletionImpl,
} from './account-deletion.flow'
import {
  completeEmailVerification as completeEmailVerificationImpl,
  requestEmailVerification as requestEmailVerificationImpl,
} from './email-verification.flow'
import { DEFAULT_FLOWS_CONFIG } from './flows.constants'
import type { Flows } from './flows.types'
import { impersonate as impersonateImpl, releaseImpersonation as releaseImpersonationImpl } from './impersonate.flow'
import {
  completePasswordReset as completePasswordResetImpl,
  requestPasswordReset as requestPasswordResetImpl,
} from './password-reset.flow'
import { linkProvider as linkProviderImpl, unlinkProvider as unlinkProviderImpl } from './provider-link.flow'
import {
  advanceSignUp as advanceSignUpImpl,
  beginSignUp as beginSignUpImpl,
  completeSignUp as completeSignUpImpl,
  getSignUpFlow as getSignUpFlowImpl,
} from './signup.flow'

export class FlowsImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> {
  private readonly _deps: Flows.Deps<Profile>

  constructor(
    sessions: SessionsImpl,
    identities: IdentitiesImpl<Profile>,
    providers: Providers<Profile>,
    transport: Transport.ITransport,
    events: Events.IBus,
    ctxFactory: (tenantId?: string) => Provider.Context<Profile>,
    requirePasswords: () => PasswordsImpl,
    requireMfa: () => MfaFacet,
    cfg: Flows.Cfg = DEFAULT_FLOWS_CONFIG,
  ) {
    this._deps = { sessions, identities, providers, transport, events, ctxFactory, requirePasswords, requireMfa, cfg }
  }

  /** Expose deps for testing extracted flow functions directly. */
  get deps(): Flows.Deps<Profile> {
    return this._deps
  }

  /** The `startSession` intent is interpreted here; the rest flow through to the caller. */
  async signIn(opts: Flows.SignInOptions): Promise<Flows.SignInOutcome> {
    const { sessions, identities, providers, transport, events, ctxFactory, cfg } = this._deps

    const providerId = canonicalProviderId(opts.providerId)
    if (providerId === null || !providers.has(providerId)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: echoableProviderId(opts.providerId),
        detail: 'unknown provider id',
      })
    }

    const ctx = ctxFactory(opts.tenantId)
    const rawIntents = await providers.complete(providerId, ctx, opts.input)

    // SECURITY: acted on, not merely stripped. `Provider.Intent`'s contract says this signal is
    // "consumed and stripped" here, and only the stripping happened - so a provider answering
    // `startSession` alongside `requireMfa` got a plain session at the AAL it asked for and its demand
    // for a second factor left with the filter. Nothing shipped emits one, but the provider list is open.
    const mfaIntent = rawIntents.find(
      (i): i is Extract<Provider.InternalIntent, { type: 'requireMfa' }> => i.type === 'requireMfa',
    )
    if (mfaIntent) {
      throw new AuthError('AUTH_STEP_UP_REQUIRED', {
        challenge: { methods: mfaIntent.methods, reason: 'provider-required-mfa' },
      })
    }

    const startIntent = rawIntents.find(
      (i): i is Extract<Provider.InternalIntent, { type: 'startSession' }> => i.type === 'startSession',
    )
    if (!startIntent) {
      const adapterIntents = rawIntents.filter(
        (i): i is Provider.Intent => i.type !== 'startSession' && i.type !== 'requireMfa',
      )
      return { session: null, sid: '', intents: adapterIntents }
    }

    const identity = await identities.getById(startIntent.identityId).orNull()
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
      // Already loaded above to gate the signin; save listeners a re-read.
      identity,
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

  /** Builds the same context `signIn` does. */
  async beginProvider(
    providerId: string,
    input: unknown,
    opts: { tenantId?: string } = {},
  ): Promise<Provider.Intent[]> {
    const { providers, ctxFactory } = this._deps
    const canonical = canonicalProviderId(providerId)
    if (canonical === null || !providers.has(canonical)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: echoableProviderId(providerId),
        detail: 'unknown provider id',
      })
    }
    return providers.begin(canonical, ctxFactory(opts.tenantId), input)
  }

  /** Revoke the current session and emit Transport.revoke intents. */
  async signOut(sid: string): Promise<{ intents: Provider.Intent[] }> {
    const { sessions, transport } = this._deps
    // `sessions.revoke` refuses a malformed sid rather than ignoring it, and a sign-out is not the place to
    // raise that: this keeps a non-string sid off the bus and out of the transport, where revoke would be a
    // no-op anyway.
    if (typeof sid === 'string' && sid.length > 0 && sid.length <= 4096) {
      await sessions.revoke(sid).orNull()
    }
    return { intents: transport.revoke() }
  }

  /** Whether the session already satisfies a step-up requirement; otherwise a challenge naming the
   *  methods that would. */
  async checkStepUp(session: Sessions.Me, requirement: Flows.StepUpRequirement): Promise<Flows.StepUpOutcome> {
    const requiredAal: Sessions.AAL = requirement.aal ?? 2
    const methods = requirement.methods ?? ['totp']
    const freshness = requirement.freshness

    if (session.aal >= requiredAal && session.fresh) {
      // Fail-closed: a non-finite rotatedAt would slip the freshness gate, and so would a future one -
      // `now - rotatedAt` goes negative and no window is ever exceeded. Bounded both ways.
      if (freshness !== undefined) {
        const rotatedAtMs =
          session.rotatedAt instanceof Date
            ? session.rotatedAt.getTime()
            : typeof session.rotatedAt === 'number' && Number.isFinite(session.rotatedAt)
              ? session.rotatedAt
              : Number.NaN
        if (!Number.isFinite(rotatedAtMs) || Math.abs(Date.now() - rotatedAtMs) > freshness) {
          return { satisfied: false, reason: 'fresh-required', methods }
        }
      }
      return { satisfied: true, session, sid: '', intents: [] }
    }
    return { satisfied: false, reason: 'mfa-required', methods }
  }

  /**
   * Verifies the factor and rotates the session to the higher AAL with it recorded.
   *
   * SECURITY: the factor is looked up in the session's own tenant and no parameter can name another.
   * Credentials are tenant-scoped and identities are not, so a second input would let a factor enrolled in
   * tenant B satisfy a step-up in tenant A.
   */
  async completeStepUp(opts: {
    currentSid: string
    method: 'totp' | 'backup-code'
    code: string
  }): Promise<{ session: Sessions.Me; sid: string; intents: Provider.Intent[] }> {
    if (opts.method !== 'totp' && opts.method !== 'backup-code') {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    if (typeof opts.code !== 'string' || opts.code.length === 0 || opts.code.length > 64) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    const { sessions, requireMfa, transport, ctxFactory } = this._deps
    const mfa = requireMfa()
    const resolved = await sessions.getBySid(opts.currentSid).orNull()
    if (!resolved?.identityId) {
      throw new AuthError('AUTH_UNAUTHENTICATED')
    }
    // The session's tenant, not the caller's claim about it. A global session (`tenantId: null`) reads
    // unscoped, the rule `Credential.Store` applies everywhere else.
    const tenant: TenantContext = resolved.tenantId !== null ? { tenantId: resolved.tenantId } : {}
    // SECURITY: bounded here, because nothing else bounds this gate - `MfaFacet` holds no limiter, so
    // every call site has to bring its own and this one did not. A TOTP is six digits and
    // `matchTotpStep` accepts a drift window, which is guessable online in minutes by exactly the
    // caller a second factor is for: one holding the password and not the phone.
    const ctx = ctxFactory(resolved.tenantId ?? undefined)
    const limited = await ctx.limiter.consume(`stepup:${resolved.identityId}`)
    if (!limited.ok) await refuseRateLimited(ctx.events, limited, resolved.identityId)
    const ok =
      opts.method === 'totp'
        ? await mfa.verifyTotp(resolved.identityId, opts.code, tenant)
        : await mfa.verifyBackupCode(resolved.identityId, opts.code, tenant)
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
      // Unconditional: `Sessions.Me.tenantId` is `string | null` and never `undefined`, so the guard this
      // replaces always fired while reading as though it sometimes did not. The rotated session stays in
      // the tenant it was in.
      tenantId: resolved.tenantId,
    })
    const intents = transport.issue(sid, session, { fresh: true, absolute: false, csrfToken })
    return { session, sid, intents }
  }

  /** Request a password reset. Always answers successfully, so it enumerates nothing; a single-use
   *  token is minted, hashed at rest and dispatched when the identity exists. `channels` and
   *  `findIdentityByEmail` are supplied by the host, which owns that wiring. */
  async requestPasswordReset(opts: {
    input: Flows.PasswordResetRequestInput
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    channels: Partial<Record<'email' | 'sms' | 'webpush', import('~/channels/channels.types').Channel.Channel>>
    tenantId?: string
  }): Promise<{ ok: true }> {
    return requestPasswordResetImpl(this._deps, opts)
  }

  /**
   * Verifies the single-use token, ends every session the old password could still hold open, then sets the
   * new one, in that order: a failed revoke must not leave old sessions live under the new password.
   *
   * SECURITY: an account with MFA enrolled needs a fresh AAL=2 session of that identity in `currentSid`, and
   * repeated refusals are rate limited and eventually consume the token. `intents` is empty for the ordinary
   * email-link reset; when `currentSid` names a live session it is rotated rather than swept, and its
   * replacement rides there.
   */
  async completePasswordReset(
    input: Flows.PasswordResetCompleteInput & { currentSid?: string; tenantId?: string },
  ): Promise<{ ok: true; intents: Provider.Intent[] }> {
    return completePasswordResetImpl(this._deps, input)
  }

  /** Mint and dispatch an email-verification token, rate limited per identity so a "didn't get the
   *  email" button cannot flood the channel. An already-verified identity is a no-op that answers the
   *  same way, so the caller learns nothing about its status. */
  async requestEmailVerification(opts: Flows.EmailVerificationRequestInput): Promise<{ ok: true }> {
    return requestEmailVerificationImpl(this._deps, opts)
  }

  /** Spends the verification token and marks the address verified. */
  async completeEmailVerification(
    input: Flows.EmailVerificationCompleteInput,
  ): Promise<{ identity: Identities.Me<Profile>; identityId: string }> {
    return completeEmailVerificationImpl(this._deps, input)
  }

  /** Mint and dispatch a confirmation token, leaving the identity untouched until
   *  {@link FlowsImpl.completeAccountDeletion}. Single-use, TTL'd (default 30 min), and a fresh
   *  request wipes the prior token so only the latest verifies. */
  async requestAccountDeletion(opts: Flows.AccountDeletionRequestInput): Promise<{ ok: true }> {
    return requestAccountDeletionImpl(this._deps, opts)
  }

  /** Soft-deletes the identity, revokes its sessions, and mints the single-use undo token
   *  `cancelAccountDeletion` accepts, handed back as plaintext once and mailed for you given `channels`. */
  async completeAccountDeletion(input: Flows.AccountDeletionCompleteInput): Promise<{
    identity: Identities.Me<Profile>
    identityId: string
    restorableUntil: number
    cancellationToken: string
  }> {
    return completeAccountDeletionImpl(this._deps, input)
  }

  /** Undo inside the grace window, through either the undo token (the user's route) or an `authorize`
   *  callback (the operator's). One or the other: both or neither is `AUTH_MISCONFIGURED`. */
  async cancelAccountDeletion(
    input: Flows.AccountDeletionCancelInput,
  ): Promise<{ identity: Identities.Me<Profile>; identityId: string }> {
    return cancelAccountDeletionImpl(this._deps, input)
  }

  /**
   * Begin a multi-step signup: create the identity with `emailVerified=false` and answer with a handle the
   * caller persists and each stage advances, until `complete()` issues the session. `username` comes from the
   * email local part when `initialProfile` carries none, because the type and the Postgres CHECK both demand
   * one. State lives in the credentials store under `kind: 'recovery'` with `metadata.purpose: 'signup-flow'`,
   * which is what tells four token kinds apart inside the one kind.
   *
   * WARN: rate-limited on the canonical address, but the identity row is written before anything proves
   * the caller owns it. See `docs/superpowers/DECISIONS.md` D1.
   */
  async beginSignUp(opts: {
    email: string
    required?: Flows.SignUpStage[]
    initialProfile?: Partial<Profile>
    tenantId?: string
  }): Promise<{ flow: Flows.SignUpFlowState<Profile>; flowToken: string }> {
    return beginSignUpImpl(this._deps, opts)
  }

  /** The sign-up flow behind `flowToken`. Rejects `AUTH_CREDENTIAL_NOT_FOUND` when there is no live flow -
   *  a miss, a revoked row, an elapsed TTL and unreadable metadata are one answer, and `orNull()` reads
   *  them back as null. */
  getSignUpFlow(flowToken: string, tenantId?: string): Answer.Me<Flows.SignUpFlowState<Profile>> {
    return answer(getSignUpFlowImpl(this._deps, flowToken, tenantId))
  }

  /** Carries a partial sign-up to its next stage, answering a fresh flow token. */
  async advanceSignUp(opts: {
    flowToken: string
    stage: Flows.SignUpStage
    profilePatch?: Partial<Profile>
    tenantId?: string
  }): Promise<Flows.SignUpFlowState<Profile>> {
    return advanceSignUpImpl(this._deps, opts)
  }

  /** Closes a staged sign-up: creates the identity and issues the session. */
  async completeSignUp(opts: {
    flowToken: string
    aal?: Sessions.AAL
    factors?: Sessions.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    previousSid?: string
  }): Promise<Flows.SignInOutcome> {
    return completeSignUpImpl(this._deps, opts)
  }

  /** Refuses to issue an `actingAs` session until the supplied `authorize` callback approves it; iam
   *  consumers wire `engine.authorize()` here.
   *  SECURITY: never pass `() => true`, which defeats the invariant this exists to keep. */
  async impersonate(
    opts: Flows.ImpersonateOptions & {
      authorize: (realSession: Sessions.Me, targetIdentityId: string) => Promise<boolean>
    },
  ): Promise<Flows.ImpersonateOutcome> {
    return impersonateImpl(this._deps, opts)
  }

  /** Attach a provider identity to an existing account. `providerSub` is unverifiable from here, so
   *  the mandatory `authorize` callback is where the host vouches for it. */
  async linkProvider(
    opts: Flows.LinkProviderInput<Profile>,
  ): Promise<{ identity: Identities.Me<Profile>; identityId: string; providerId: string }> {
    return linkProviderImpl(this._deps, opts)
  }

  /** Drops one provider link, refusing the one that would leave the identity unable to sign in. */
  async unlinkProvider(
    opts: Flows.UnlinkProviderInput,
  ): Promise<{ identity: Identities.Me<Profile>; identityId: string; providerId: string }> {
    return unlinkProviderImpl(this._deps, opts)
  }

  /** Ends the impersonation and mints the operator a session of their own. `session` and `sid` are null
   *  and empty only when the operator's identity is gone, and the bearer is cleared instead. */
  async releaseImpersonation(
    impersonationSid: string,
  ): Promise<{ session: Sessions.Me | null; sid: string; intents: Provider.Intent[] }> {
    return releaseImpersonationImpl(this._deps, impersonationSid)
  }
}

export function flows<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  sessions: SessionsImpl,
  identities: IdentitiesImpl<Profile>,
  providers: Providers<Profile>,
  transport: Transport.ITransport,
  events: Events.IBus,
  ctxFactory: (tenantId?: string) => Provider.Context<Profile>,
  requirePasswords: () => PasswordsImpl,
  requireMfa: () => MfaFacet,
  cfg?: Flows.Cfg,
): FlowsImpl<Profile> {
  return new FlowsImpl(
    sessions,
    identities,
    providers,
    transport,
    events,
    ctxFactory,
    requirePasswords,
    requireMfa,
    cfg,
  )
}
