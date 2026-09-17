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
    createdBy: string | null
    updatedBy: string | null
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
    /** Atomic shallow-merge `patch` into `metadata` + version bump. Throws `AUTH_CREDENTIAL_NOT_FOUND` if
     *  `id` is unknown, which is the only failure it has: the merge is one statement, so nothing goes stale. */
    patchMetadata(id: string, patch: Record<string, unknown>, ctx: TenantContext): Promise<Me>
    /**
     * The three removals answer with what they removed rather than `void`:
     * `null` / `[]` when nothing matched. A caller that needs to know what a
     * removal did, such as which key was revoked or how many factors were dropped,
     * should not have to read the rows back, and after a `delete` there is
     * nothing left to read at all.
     */
    revoke(id: string, ctx: TenantContext): Promise<Me | null>
    /**
     * Revoke every live row of `kind: 'oauth'` whose metadata carries `familyId`, and answer how many moved.
     * RFC 6749 section 10.4: a replayed refresh token kills the whole family, so a store that cannot do this
     * leaves every sibling token usable while `AUTH_OAUTH_REUSE_DETECTED` reports the family revoked.
     */
    revokeFamily(familyId: string, ctx: TenantContext): Promise<number>
    delete(id: string, ctx: TenantContext): Promise<Me | null>
    deleteByKind(identityId: string, kind: Kind, ctx: TenantContext): Promise<Me[]>
    /**
     * `deleteByKind` narrowed to one `metadata.purpose`, in one round trip.
     *
     * `kind: 'recovery'` carries a dozen meanings - a reset token, a verification mail, an MFA
     * backup code, a remembered device - so deleting by kind alone voids six things a caller never
     * meant to touch. `deleteCredentialsByPurpose` does the same job as a list plus one delete per
     * row; this exists because the call *count* is itself observable: the password-reset flow keeps
     * its known and unknown branches to the same number of store calls so response time cannot
     * answer what the response body refuses to, and a variable-length delete pass breaks that.
     */
    deleteByKindAndPurpose(identityId: string, kind: Kind, purpose: string, ctx: TenantContext): Promise<Me[]>
  }
}
