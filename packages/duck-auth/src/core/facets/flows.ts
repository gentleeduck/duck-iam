import { AuthErrorObject } from '../errors'
import type { Events } from '../types/events'
import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'
import type { IdentitiesFacet } from './identities'
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
export class FlowsFacet<Profile = unknown> {
  constructor(
    private readonly _sessions: SessionsFacet,
    private readonly _identities: IdentitiesFacet<Profile>,
    private readonly _providers: ProvidersFacet<Profile>,
    private readonly _transport: Transport.ITransport,
    private readonly _events: Events.IBus,
    private readonly _ctxFactory: (tenantId?: string) => Provider.IContext<Profile>,
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
}
