import type { Batch } from '~/core/batch'
import type { TenantContext } from '../tenant/tenant.types'

/**
 * Stored proof of an identity. One identity has N credentials; secrets are always
 * stored hashed (passwords, magic-link tokens, recovery codes) or as public-key
 * material (passkey/WebAuthn). oauth refresh tokens stored hashed for reuse
 * detection (RFC 6749 section 10.4); plaintext is never persisted.
 */
export const AUTH_CREDENTIAL_KINDS = [
  'password',
  'passkey',
  'webauthn-mfa',
  'oauth',
  'magic-link',
  'totp',
  'recovery',
  'api-key',
] as const

export namespace Credential {
  export type Kind = (typeof AUTH_CREDENTIAL_KINDS)[number]

  export type Me = {
    id: string
    identityId: string
    tenantId: string | null
    kind: Kind
    /** Hash, public key, or encrypted token. Never plaintext. */
    secret: string
    /** Absent metadata is stored/returned as `null`, never `undefined`. */
    metadata: Record<string, unknown> | null
    version: number
    createdAt: Date
    lastUsedAt: Date | null
    expiresAt: Date | null
    revokedAt: Date | null
  }

  /**
   * Input to `Store.upsert`. The store stamps `id`/`version`/`createdAt`;
   * every field is explicit — the facet coalesces optional public inputs to
   * `null` before passing this type. Nullable columns carry `T | null`.
   */
  export type UpsertInput = {
    identityId: string
    kind: Kind
    secret: string
    tenantId: string | null
    metadata: Record<string, unknown> | null
    lastUsedAt: Date | null
    expiresAt: Date | null
    revokedAt: Date | null
  }

  export type Store = {
    findById(id: string, ctx: TenantContext): Promise<Me | null>
    listByIdentity(identityId: string, kind: Kind | null, ctx: TenantContext): Promise<Me[]>
    findByProviderSub(provider: string, sub: string, ctx: TenantContext): Promise<Me | null>
    /**
     * Lookup by the **hashed** secret + kind. Used by magic-link / recovery
     * code / passwordless flows that issue an opaque token and need a
     * single-call resolution. Adapters index `(kind, secret)` for O(1) lookup.
     */
    findByHashedSecret(secretHash: string, kind: Kind, ctx: TenantContext): Promise<Me | null>
    upsert(input: UpsertInput, ctx: TenantContext): Promise<Me>
    rotate(id: string, newSecret: string, expectedVersion: number, ctx: TenantContext): Promise<Me>
    /** Atomic shallow-merge `patch` into `metadata` + version bump. Throws `AUTH/UNAUTHENTICATED` if `id` is unknown. */
    patchMetadata(id: string, patch: Record<string, unknown>, ctx: TenantContext): Promise<Me>
    revoke(id: string, ctx: TenantContext): Promise<void>
    delete(id: string, ctx: TenantContext): Promise<void>
    deleteByKind(identityId: string, kind: Kind, ctx: TenantContext): Promise<void>
    /** See `Identities.Store.withClient`. Absent means this store cannot join a transaction. */
    withClient?(client: unknown): Store

    /** Set-based delete by identity. Optional; callers loop when absent. */
    deleteByIdentities?(identityIds: readonly string[], ctx: TenantContext): Promise<Batch.Result>
  }
}
