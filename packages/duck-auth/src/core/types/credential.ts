import type { TenantContext } from './context'

/**
 * Stored proof of an identity. One identity has N credentials; secrets are always
 * stored hashed (passwords, magic-link tokens, recovery codes) or as public-key
 * material (passkey/WebAuthn). OAuth refresh tokens stored hashed for reuse
 * detection (RFC 6749 §10.4); plaintext is never persisted.
 */
export namespace Credential {
  export type Kind = 'password' | 'passkey' | 'oauth' | 'magic-link' | 'totp' | 'recovery' | 'api-key'

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
    findById(id: string, ctx: TenantContext): Promise<ICredential | null>
    listByIdentity(identityId: string, kind: Kind | undefined, ctx: TenantContext): Promise<ICredential[]>
    findByProviderSub(provider: string, sub: string, ctx: TenantContext): Promise<ICredential | null>
    upsert(input: Omit<ICredential, 'id' | 'version' | 'createdAt'>, ctx: TenantContext): Promise<ICredential>
    rotate(id: string, newSecret: string, expectedVersion: number, ctx: TenantContext): Promise<ICredential>
    revoke(id: string, ctx: TenantContext): Promise<void>
    delete(id: string, ctx: TenantContext): Promise<void>
    deleteByKind(identityId: string, kind: Kind, ctx: TenantContext): Promise<void>
  }
}
