import type { Events } from '~/core/events/events.types'
import type { Limiter } from '~/limiters'
import type { Anomaly } from '../anomaly'
import type { AuthCaptcha } from '../captcha'
import type { AuthDefine } from '../config/config.types'
import type { Credential } from '../credentials/credentials.types'
import type { Hijack } from '../hijack/hijack.types'
import type { IdempotencyInput } from '../idempotency'
import type { Identities } from '../identities/identities.types'
import type { Org } from '../orgs/orgs.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'

/** What the `AuthEngine` constructor takes, and the store bag it binds. */
export namespace Engine {
  /** What the engine is handed: an adapter, or facets picked off one and mixed, redis sessions beside a
   *  drizzle identities store say. `withClient` rebinds the whole bag onto a transaction handle at once
   *  because those facets share a connection; a hand-built mix has none, so `withTransaction` refuses
   *  rather than leave a facet behind on the engine's own connection. */
  export type Stores<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    OrgMeta = unknown,
  > = {
    identities: Identities.Store<Profile>
    sessions: Sessions.Store
    credentials: Credential.Store
    orgs?: Org.Store<OrgMeta>
    withClient?(client: unknown): Stores<Profile, OrgMeta>
  }

  /**
   * Configuration for an {@link Engine} instance.
   *
   * @template Profile - Shape of the user profile stored on identities.
   * @template Tenant - Tenant discriminator type.
   * @template OrgMeta - Shape of organization metadata.
   */
  export type Cfg<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > = {
    /** The deployment's public origin; links and redirects are built against it. */
    baseUrl: string
    /** How a session is carried on the wire: a cookie, a bearer token, or a composite of both. */
    transport: Transport.ITransport
    /** The persistence contracts the engine reads and writes through. */
    stores: Stores<Profile, OrgMeta>
    /** The budget the flows spend against; without one nothing is throttled. */
    limiter?: Limiter.Me
    /** Sign-in providers and attach-only facets, or thunks building one from the constructed engine and its
     *  channels. The constructor resolves them, so `new AuthEngine` and `createAuth` behave alike. */
    providers?: AuthDefine.IProviderEntry<Profile, Tenant, OrgMeta>[]
    /** A facet, or a bare store to wrap in one, mirroring `limiter`:
     *  `idempotency: redisIdempotency({ prefix: 'auth:idem', redis })`. */
    idempotency?: IdempotencyInput
    /**
     * Surfaced as `auth.captcha`, so a host has one place to reach for it. Turnstile, hCaptcha and reCAPTCHA
     * v3 ship in `core/captcha`. Omitted, every call answers
     * `{ success: false, errorCodes: ['captcha-not-configured'] }`, and `authNullCaptchaVerifier()` opts
     * into always-pass.
     *
     * SECURITY: a missing secret must not read as a solved challenge.
     */
    captcha?: AuthCaptcha.IVerifier
    /** Forwarded to provider thunks, magic-link and OTP among them. */
    channels?: AuthDefine.IChannels
    /** Where lifecycle events are published; some `strict()` checks need a bus to be reachable. */
    events?: Events.IBus
    session?: {
      /** Sliding lifetime in ms. */
      ttlMs?: number
      /** Hard cap in ms, which no rotation or touch moves. */
      absoluteTtlMs?: number
      /** How long after a factor a session still counts as fresh, in ms. */
      freshnessMs?: number
    }
    identities?: {
      /** How long a soft-deleted identity stays recoverable before erasure, in ms. */
      softDeleteGracePeriodMs?: number
      /** Max serialised profile size in UTF-8 bytes, 16 KiB by default; `0` disables the cap. */
      profileMaxBytes?: number
    }
    /** Fills `created_by`, `updated_by` and `deleted_by` when no `withActor` scope is active; wire it to the
     *  request context the host framework already has. Answering `null` or `undefined` records no actor, which is
     *  truthful and never swapped for a placeholder. Process-wide, see `setDefaultActorResolver`. */
    resolveActor?: () => string | null | undefined
    /** Session-hijack policy: what counts as drift, and what to do about it. */
    hijack?: Hijack.Cfg
    /** Scoring thresholds and per-signal reactions, merged over the defaults the way `hijack` is. */
    anomaly?: Partial<Anomaly.Cfg>
    /** Phantom field carrying the tenant type through inference; never assign it a value. */
    __tenantBrand?: Tenant
  }

  /** Result shape of `resolveSession`. `identity` is null for a guest session, one with no `identityId`:
   *  an identity that could not be read rejects `AUTH_SESSION_IDENTITY_ERASED` instead, so the null here
   *  states a session kind rather than a failed lookup. */
  export type ResolveResult<Profile extends Identities.ProfileMetadataBase> = {
    session: Sessions.Me
    identity: Identities.Me<Profile> | null
    /** The aggregate anomaly decision, present only when a detector is registered and
     *  `opts.requestSnapshot` was supplied. Branch on `anomaly.decision`. */
    anomaly?: Anomaly.Result
  }
}
