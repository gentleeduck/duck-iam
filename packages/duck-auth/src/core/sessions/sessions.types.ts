import type { Batch } from '~/core/batch'
/** Session domain + lifecycle types — the single `Session` namespace for the sessions subject. */

import type { Identities } from '../identities'
import type { TenantContext } from '../tenant/tenant.types'

/**
 * Authenticated (or guest, or API-key) bearer of access. Issued by the configured
 * Transport; resolved on every authed request. AAL + factor model follows NIST 800-63B.
 */
export const AUTH_SESSION_KINDS = ['guest', 'user', 'apikey'] as const

export const AUTH_SESSION_FACTOR_METHODS = [
  'password',
  'passkey',
  'totp',
  'oauth',
  'saml',
  'magic-link',
  'webauthn',
  'sms',
  'api-key',
  'backup-code',
] as const

export namespace Sessions {
  /** NIST 800-63B Authentication Assurance Levels. */
  export type AAL = 1 | 2 | 3

  export type FactorMethod = (typeof AUTH_SESSION_FACTOR_METHODS)[number]

  export interface Factor {
    method: FactorMethod
    completedAt: Date
  }

  export type Kind = (typeof AUTH_SESSION_KINDS)[number]

  /** Audit-visible impersonation envelope; absent on non-impersonation sessions. */
  export type ActingAs = {
    realIdentityId: string
    startedAt: Date
    reason: string
    expiresAt: Date
  }

  export type Me = {
    id: string
    identityId: string | null
    tenantId: string | null
    kind: Kind
    aal: AAL
    factors: Factor[]
    /** Per-session CSRF token hash (sha-256). Cookie carries the plaintext under __Host-. */
    csrfHash: string | null
    /** Captured at create; used by hijack-detection policy. */
    ip: string | null
    userAgent: string | null
    fingerprint: string | null
    createdAt: Date
    rotatedAt: Date
    expiresAt: Date
    absoluteExpiresAt: Date
    fresh: boolean
    /**
     * The impersonation window, when one is open. This is also the only case in
     * which a session's author differs from its subject, which is why the row
     * carries no `createdBy`: for every other session `identityId` already
     * answers "who opened this", and a column repeating it can only drift.
     */
    actingAs: ActingAs | null
  }

  /**
   * Input to `Store.create`. Callers provide the identifying + lifecycle
   * fields; every nullable column is explicit `T | null` — the facet
   * coalesces optional public inputs before passing this type.
   */
  export type CreateInput = Omit<Me, 'tenantId' | 'csrfHash' | 'ip' | 'userAgent' | 'fingerprint' | 'actingAs'> & {
    tenantId: string | null
    csrfHash: string | null
    ip: string | null
    userAgent: string | null
    fingerprint: string | null
    actingAs: ActingAs | null
  }

  export type Store = {
    create(s: CreateInput): Promise<void>
    getByHash(sidHash: string): Promise<Me | null>
    update(id: string, patch: Partial<Me>): Promise<Me>
    delete(id: string): Promise<void>
    /**
     * Every session of an identity, optionally narrowed to one tenant.
     *
     * Identities are global - the conformance suite says so in as many words -
     * so one person is routinely a user of tenant A and of tenant B, and their
     * sessions all hang off the same id. Without the filter this read handed
     * tenant A the IP, user-agent and existence of every session tenant B had
     * issued. Sessions were the only store carrying a `tenantId` that no method
     * could select on, which `TenantContext`'s own docstring ("stores receive it
     * on every call") already said they should.
     *
     * `ctx` omitted, or `ctx.tenantId` undefined, means every tenant - the
     * behaviour every existing caller has. A set `tenantId` matches exactly, so
     * a global (`tenantId: null`) session is not visible to a named tenant.
     * Same rule as `Credential.Store`, which is the reference.
     */
    listByIdentity(identityId: string, ctx?: TenantContext): Promise<Me[]>
    /**
     * Sign an identity out. Scoped the same way as `listByIdentity`: unscoped it
     * ends every session the identity has anywhere, which is what a tenant A
     * "sign out everywhere" used to do to that person's tenant B logins.
     */
    deleteAllForIdentity(identityId: string, ctx?: TenantContext): Promise<void>
    /**
     * Periodic GC. Implementations that can run on several instances at once MUST
     * serialise themselves - `RedisSessionImpl` takes a `{prefix}:gc:lease` with
     * SET NX and no-ops when it loses. Callers schedule this; they do not lock it.
     *
     * `deleted` counts each row the run reconciled exactly once, whether its
     * record was already gone or was swept here for being past `expiresAt` or
     * `absoluteExpiresAt`.
     */
    gc(now: number): Promise<{ deleted: number }>

    /**
     * Set-based forms of the deletes above, plus the read the facet needs to
     * emit one event per session actually removed. Each is optional: the facet
     * loops when the store omits it.
     */
    deleteAllForIdentities?(identityIds: readonly string[]): Promise<Batch.Result>
    deleteMany?(ids: readonly string[]): Promise<Batch.Result>
    /** Rows about to be deleted, so the facet can emit one event per real revocation. */
    listByIdentities?(identityIds: readonly string[]): Promise<Me[]>
  }

  /** SessionsFacet tuning. */
  export type Cfg = {
    /** Sliding TTL in ms. Default 7 days. */
    ttlMs: number
    /** Hard absolute cap in ms. Default 30 days. */
    absoluteTtlMs: number
    /** Window in ms where a session counts as "fresh" since the last factor. Default 5 min. */
    freshnessMs: number
  }

  /** Facet-level mint input to {@link SessionsImpl.create}; the facet coalesces these into a `CreateInput`. */
  export type MintInput = {
    identityId: string | null
    kind: Kind
    aal: AAL
    factors: Factor[]
    tenantId?: string | null
    ip?: string | null
    userAgent?: string | null
    fingerprint?: string | null
    actingAs?: ActingAs | null
    identity?: Identities.Me | null
    /**
     * An upper bound on `expiresAt`, never an extension: the row still expires at the facet's own
     * ttl when that one is sooner. The m2m grant sets it so a session expires with the token it was
     * minted for rather than outliving it by the sessions facet's longer default.
     */
    maxExpiresAt?: Date
  }

  export interface RotateInput extends MintInput {
    /**
     * The rotation matrix. Drives whether the previous SID is revoked
     * outright, downgraded (step-up old-SID kept alive at lower AAL), or left
     * alone (impersonation start runs alongside the original session).
     */
    purpose:
      | 'signin'
      | 're-auth'
      | 'step-up'
      | 'step-down'
      | 'credential-change'
      | 'impersonate-start'
      | 'impersonate-release'
      /** A guest session becoming a named one; the guest row is revoked. */
      | 'guest-promotion'
      /**
       * The first session of a brand-new account. Distinct from `guest-promotion`
       * because `completeSignUp`'s `previousSid` is optional: most signups have no
       * prior session to promote, and calling that a promotion made the rotation
       * log describe a transition that never happened. Same revocation semantics -
       * whatever the caller came in on does not survive the account being created.
       */
      | 'sign-up'
    previousSid?: string
  }
}
