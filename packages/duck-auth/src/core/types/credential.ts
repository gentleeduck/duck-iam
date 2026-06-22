import type { AuthTenantContext } from './context'

/**
 * Stored proof of an identity. One identity has N credentials; secrets are always
 * stored hashed (passwords, magic-link tokens, recovery codes) or as public-key
 * material (passkey/WebAuthn). OAuth refresh tokens stored hashed for reuse
 * detection (RFC 6749 section 10.4); plaintext is never persisted.
 */
export namespace AuthCredential {
  export type Kind = 'password' | 'passkey' | 'webauthn-mfa' | 'oauth' | 'magic-link' | 'totp' | 'recovery' | 'api-key'

  export interface ICredential {
    id: string
    identityId: string
    tenantId?: string
    kind: Kind
    /** Hash, public key, or encrypted token. Never plaintext. */
    secret: string
    metadata?: Record<string, unknown>
    version: number
    createdAt: number
    lastUsedAt?: number
    expiresAt?: number
    revokedAt?: number
  }

  export interface IStore {
    findById(id: string, ctx: AuthTenantContext): Promise<ICredential | null>
    listByIdentity(identityId: string, kind: Kind | undefined, ctx: AuthTenantContext): Promise<ICredential[]>
    findByProviderSub(provider: string, sub: string, ctx: AuthTenantContext): Promise<ICredential | null>
    /**
     * Lookup by the **hashed** secret + kind. Used by magic-link / recovery
     * code / passwordless flows that issue an opaque token and need a
     * single-call resolution. Adapters index `(kind, secret)` for O(1) lookup.
     */
    findByHashedSecret(secretHash: string, kind: Kind, ctx: AuthTenantContext): Promise<ICredential | null>
    upsert(input: Omit<ICredential, 'id' | 'version' | 'createdAt'>, ctx: AuthTenantContext): Promise<ICredential>
    rotate(id: string, newSecret: string, expectedVersion: number, ctx: AuthTenantContext): Promise<ICredential>
    /** Atomic shallow-merge `patch` into `metadata` + version bump. Throws `AUTH/UNAUTHENTICATED` if `id` is unknown. */
    patchMetadata(id: string, patch: Record<string, unknown>, ctx: AuthTenantContext): Promise<ICredential>
    revoke(id: string, ctx: AuthTenantContext): Promise<void>
    delete(id: string, ctx: AuthTenantContext): Promise<void>
    deleteByKind(identityId: string, kind: Kind, ctx: AuthTenantContext): Promise<void>
  }
}
