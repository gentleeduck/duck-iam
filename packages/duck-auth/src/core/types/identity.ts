import type { TenantContext } from './infra'

/**
 * Credentials + orgs. (The `Identity` domain now lives in `~/core/identities/identities.types`.)
 *
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
  }
}

/**
 * Organizations + membership. Locked to core in v4.2 (Q1 decision).
 * Apps not using orgs leave the generic `Org = never`; tree-shaker drops the facet.
 */
export namespace Org {
  export type Me<Meta = unknown> = {
    id: string
    name: string
    domain: string | null
    metadata: Meta | null
    createdAt: Date
  }

  export type Membership = {
    identityId: string
    orgId: string
    /** Org-scoped roles, distinct from tenant-wide identity roles. */
    roles: string[]
    invitedAt: Date | null
    joinedAt: Date
    leftAt: Date | null
  }

  export type Store<Meta = unknown> = {
    getOrg(id: string, ctx: TenantContext): Promise<Me<Meta> | null>
    listOrgsForIdentity(identityId: string, ctx: TenantContext): Promise<Me<Meta>[]>
    listMembers(orgId: string, ctx: TenantContext): Promise<Membership[]>
    addMember(m: Omit<Membership, 'joinedAt'>, ctx: TenantContext): Promise<Membership>
    removeMember(orgId: string, identityId: string, ctx: TenantContext): Promise<void>
    setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext): Promise<void>
  }
}
