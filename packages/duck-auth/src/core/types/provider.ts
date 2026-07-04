/** Provider domain — auth providers/intents, events, anomaly detection. */
import type { Credential, Identity } from './identity'
import type { Limiter, TenantContext } from './infra'
import type { Session, Transport } from './session'

/**
 * A sign-in method. Providers are pure logic: they read stores, validate input,
 * and return Intents; the framework adapter executes the Intents against the
 * actual HTTP Request/Response. This keeps providers HTTP-free and unit-testable.
 */
export namespace AuthProvider {
  /** Cookie options surface for setCookie intents - duplicated here to avoid Transport-side cycles. */
  export interface CookieOptions extends Transport.CookieOptions {}

  /**
   * Adapter-safe intents: these are the only intents framework adapters
   * (NestJS, Express, Fastify, …) ever see. FlowsFacet consumes and strips
   * the internal `startSession` / `requireMfa` signals before returning.
   */
  export type Intent =
    | { type: 'redirect'; url: string; status?: 302 | 303 | 307 }
    | { type: 'setCookie'; name: string; value: string; options: CookieOptions }
    | { type: 'clearCookie'; name: string; options?: CookieOptions }
    | { type: 'json'; status: number; body: unknown }
    | { type: 'error'; code: string; status: number; detail?: string }

  /**
   * Full internal intent union returned by `IProvider.complete()`.
   * `startSession` and `requireMfa` are consumed by FlowsFacet; they
   * must never be forwarded to a framework adapter.
   */
  export type IInternalIntent =
    | Intent
    | {
        type: 'startSession'
        identityId: string
        factors: Session.Factor[]
        aal: Session.AAL
      }
    | { type: 'requireMfa'; identityId: string; methods: string[] }

  /** Crypto helpers exposed to providers (so they don't import node:crypto themselves). */
  export interface ICrypto {
    authRandomToken(bytes: number): string
    authSha256(s: string): string
    authTimingSafeEqual(a: string, b: string): boolean
  }

  /** Events surface - providers emit via the bus, never directly to console. */
  export interface IEvents {
    emit(event: string, payload: unknown): Promise<void>
  }

  export interface IContext<Profile = unknown> {
    stores: {
      identities: Identity.Store<Profile>
      sessions: Session.Store
      credentials: Credential.Store
    }
    tenant: TenantContext
    baseUrl: string
    limiter: Limiter.ILimiter
    events: IEvents
    crypto: ICrypto
  }

  export interface IProvider<BeginIn = unknown, CompleteIn = unknown, Profile = unknown> {
    id: string
    /** Open string so custom providers declare their own kind without patching the type. */
    kind: string
    begin(ctx: IContext<Profile>, input: BeginIn): Promise<Intent[]>
    complete(ctx: IContext<Profile>, input: CompleteIn): Promise<IInternalIntent[]>
  }
}

/**
 * Typed event bus. Reference impl is in-memory; production swaps in Redis pub/sub
 * (`RedisEvents`) or Kafka (`KafkaEvents`) for multi-process / multi-region listeners.
 * Audit envelope (impersonation) flows on every event when present.
 */
export namespace Events {
  export interface AuditEnvelope {
    /** When the session is impersonating, real subject is recorded on every event. */
    actingAs?: Session.ActingAs
    /** Optional iam decision id when an action was authorized via iam-auth-bridge. */
    iamDecisionId?: string
  }

  export interface EventMap {
    'session.created': {
      session: Session.Me
      identity: Identity.Me | null
      audit?: AuditEnvelope
    }
    'session.rotated': { session: Session.Me; audit?: AuditEnvelope }
    'session.revoked': {
      sessionId: string
      identityId: string | null
      audit?: AuditEnvelope
    }
    'signin.success': {
      identity: Identity.Me
      factors: Session.Factor[]
      audit?: AuditEnvelope
    }
    'signin.failed': {
      providerId: string
      reason: string
      ip?: string
      audit?: AuditEnvelope
    }
    'signup.completed': { identity: Identity.Me; audit?: AuditEnvelope }
    lockout: { identityId: string; until: number; audit?: AuditEnvelope }
    'mfa.enrolled': {
      identityId: string
      method: Session.FactorMethod
      audit?: AuditEnvelope
    }
    'mfa.removed': {
      identityId: string
      method: Session.FactorMethod
      audit?: AuditEnvelope
    }
    'identity.linked': {
      identityId: string
      providerId: string
      audit?: AuditEnvelope
    }
    'identity.merged': {
      survivorId: string
      mergedFromId: string
      audit?: AuditEnvelope
    }
    'identity.impersonated': {
      realIdentityId: string
      targetIdentityId: string
      reason: string
      iamDecisionId?: string
    }
    'recovery.password.requested': { identityId: string; audit?: AuditEnvelope }
    'recovery.password.completed': { identityId: string; audit?: AuditEnvelope }
    'recovery.mfa.escalated': {
      identityId: string
      ticketId: string
      audit?: AuditEnvelope
    }
    suspicious: {
      identityId?: string
      signal: string
      score: number
      meta: Record<string, unknown>
      audit?: AuditEnvelope
    }
    'maintenance.on': { message?: string; retryAfter?: number }
    'maintenance.off': Record<string, never>
  }

  export type EventName = keyof EventMap
  export type Handler<K extends EventName> = (payload: EventMap[K]) => void | Promise<void>
  export type Unsubscribe = () => void

  export interface IBus {
    on<K extends EventName>(event: K, handler: Handler<K>): Unsubscribe
    emit<K extends EventName>(event: K, payload: EventMap[K]): Promise<void>
  }
}

/**
 * Anomaly-detection adapter contract. Each detector evaluates a request
 * + session and returns zero or more signals. Apps register one or more
 * detectors; AuthEngine aggregates the scores and emits `suspicious` when
 * thresholds trip
 */
export namespace Anomaly {
  export type Kind = 'impossible-travel' | 'new-device' | 'high-velocity' | 'off-hours' | 'concurrent-geo'

  export interface Signal {
    kind: Kind
    /** 0..1; higher = more suspicious. */
    score: number
    evidence: Record<string, unknown>
  }

  export interface RequestSnapshot {
    ip?: string
    userAgent?: string
    geo?: { country?: string; lat?: number; lon?: number }
    now: number
  }

  export interface IDetector {
    readonly id: string
    evaluate(ctx: { session: Session.Me; identity: Identity.Me; req: RequestSnapshot }): Promise<Signal[]>
  }
}
