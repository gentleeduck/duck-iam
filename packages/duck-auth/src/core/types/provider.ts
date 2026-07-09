/** Provider domain — auth providers/intents, events, anomaly detection. */

import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'
import type { Credential } from './identity'
import type { Limiter, TenantContext } from './infra'
import type { Transport } from './session'

/**
 * A sign-in method. Providers are pure logic: they read stores, validate input,
 * and return Intents; the framework adapter executes the Intents against the
 * actual HTTP Request/Response. This keeps providers HTTP-free and unit-testable.
 */
export namespace Provider {
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
  export type InternalIntent =
    | Intent
    | {
        type: 'startSession'
        identityId: string
        factors: Session.Factor[]
        aal: Session.AAL
      }
    | { type: 'requireMfa'; identityId: string; methods: string[] }

  /** Crypto helpers exposed to providers (so they don't import node:crypto themselves). */
  export type Crypto = {
    authRandomToken(bytes: number): string
    authSha256(s: string): string
    authTimingSafeEqual(a: string, b: string): boolean
  }

  /** Events surface - providers emit via the bus, never directly to console. */
  export type Events = {
    emit(event: string, payload: unknown): Promise<void>
  }

  export type Context<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> = {
    stores: {
      identities: Identity.Store<Profile>
      sessions: Session.Store
      credentials: Credential.Store
    }
    tenant: TenantContext
    baseUrl: string
    limiter: Limiter.Limiter
    events: Events
    crypto: Crypto
  }

  export interface Me<
    BeginIn = unknown,
    CompleteIn = unknown,
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  > {
    id: string
    /** Open string so custom providers declare their own kind without patching the type. */
    kind: string
    begin(ctx: Context<Profile>, input: BeginIn): Promise<Intent[]>
    complete(ctx: Context<Profile>, input: CompleteIn): Promise<InternalIntent[]>
  }

  /**
   * A capability module (mechanism A). Carries an optional sign-in provider
   * plus an `attach` hook that builds and mounts the capability's facet onto
   * the engine. Built by `passwordProvider()`, `mfaProvider()`, etc. Passing a
   * bare {@link Me} to `config.providers` is still accepted; the engine
   * normalizes it to `{ name: p.id, provider: p }`.
   */
  export interface ProviderModule<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > {
    /** Stable capability name; the engine rejects a second module with the same name. */
    name: string
    /** Optional sign-in provider registered into ProvidersFacet at attach time. */
    provider?: Me<unknown, unknown, Profile>
    /** Builds this capability's facet from engine core + own config, then mounts it. */
    attach?(engine: import('../engine/engine').AuthEngine<Profile, Tenant, OrgMeta>): void
  }
}

/**
 * Typed event bus. Reference impl is in-memory; production swaps in Redis pub/sub
 * (`RedisEvents`) or Kafka (`KafkaEvents`) for multi-process / multi-region listeners.
 * Audit envelope (impersonation) flows on every event when present.
 */
export namespace Events {
  export interface Envelope {
    /** When the session is impersonating, real subject is recorded on every event. */
    actingAs?: Session.ActingAs
    /** Optional iam decision id when an action was authorized via iam-auth-bridge. */
    iamDecisionId?: string
  }

  export interface EventMap {
    'session.created': {
      session: Session.Me
      identity: Identity.Me | null
      audit?: Envelope
    }
    'session.rotated': { session: Session.Me; audit?: Envelope }
    'session.revoked': {
      sessionId: string
      identityId: string | null
      audit?: Envelope
    }
    'signin.success': {
      identity: Identity.Me
      factors: Session.Factor[]
      audit?: Envelope
    }
    'signin.failed': {
      providerId: string
      reason: string
      ip?: string
      audit?: Envelope
    }
    'signup.completed': { identity: Identity.Me; audit?: Envelope }
    lockout: { identityId: string; until: number; audit?: Envelope }
    'mfa.enrolled': {
      identityId: string
      method: Session.FactorMethod
      audit?: Envelope
    }
    'mfa.removed': {
      identityId: string
      method: Session.FactorMethod
      audit?: Envelope
    }
    'identity.linked': {
      identityId: string
      providerId: string
      audit?: Envelope
    }
    'identity.merged': {
      survivorId: string
      mergedFromId: string
      audit?: Envelope
    }
    'identity.impersonated': {
      realIdentityId: string
      targetIdentityId: string
      reason: string
      iamDecisionId?: string
    }
    'recovery.password.requested': { identityId: string; audit?: Envelope }
    'recovery.password.completed': { identityId: string; audit?: Envelope }
    'recovery.mfa.escalated': {
      identityId: string
      ticketId: string
      audit?: Envelope
    }
    suspicious: {
      identityId?: string
      signal: string
      score: number
      meta: Record<string, unknown>
      audit?: Envelope
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

  export type Detector = {
    readonly id: string
    evaluate(ctx: { session: Session.Me; identity: Identity.Me; req: RequestSnapshot }): Promise<Signal[]>
  }
}
