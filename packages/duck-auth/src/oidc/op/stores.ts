/**
 * In-memory stores for the OIDC OP. Suitable for tests and single-instance
 * dev servers. Production deployments wire one of the DB adapters by
 * implementing the same interfaces.
 */

import type { OidcOP } from './types'

/** In-memory `AuthOidcOP.IClientStore`. Maps `client_id` → registered client. */
export class AuthMemoryClientStore implements OidcOP.ClientStore {
  private rows = new Map<string, OidcOP.Client>()
  async findById(client_id: string): Promise<OidcOP.Client | null> {
    return this.rows.get(client_id) ?? null
  }
  async insert(c: OidcOP.Client): Promise<void> {
    if (this.rows.has(c.client_id)) {
      throw new Error(`AuthMemoryClientStore: client_id '${c.client_id}' already registered`)
    }
    this.rows.set(c.client_id, c)
  }
}

/** In-memory `AuthOidcOP.ICodeStore`. Codes are single-use; `consume` deletes them. */
export class AuthMemoryCodeStore implements OidcOP.CodeStore {
  private rows = new Map<string, OidcOP.Code>()
  async insert(c: OidcOP.Code): Promise<void> {
    this.rows.set(c.code, c)
  }
  async consume(code: string, now: number): Promise<OidcOP.Code | null> {
    const row = this.rows.get(code)
    if (!row) return null
    this.rows.delete(code)
    if (row.exp <= now) return null
    return row
  }
}

/** In-memory `AuthOidcOP.IAccessTokenStore`. Keyed by `token_hash`; expired tokens evicted lazily on read. */
export class AuthMemoryAccessTokenStore implements OidcOP.AccessTokenStore {
  private rows = new Map<string, OidcOP.AccessToken>()
  async insert(t: OidcOP.AccessToken): Promise<void> {
    this.rows.set(t.token_hash, t)
  }
  async findByHash(hash: string, now: number): Promise<OidcOP.AccessToken | null> {
    const row = this.rows.get(hash)
    if (!row) return null
    if (row.exp <= now) {
      this.rows.delete(hash)
      return null
    }
    return row
  }
  async revokeByHash(hash: string): Promise<void> {
    this.rows.delete(hash)
  }
}

/** In-memory `AuthOidcOP.IRefreshTokenStore`. Supports RTR family revocation via `revokeFamily`. */
export class AuthMemoryRefreshTokenStore implements OidcOP.RefreshTokenStore {
  private rows = new Map<string, OidcOP.RefreshToken>()
  async insert(t: OidcOP.RefreshToken): Promise<void> {
    this.rows.set(t.token_hash, t)
  }
  async findByHash(hash: string, now: number): Promise<OidcOP.RefreshToken | null> {
    const row = this.rows.get(hash)
    if (!row) return null
    if (row.exp <= now) {
      this.rows.delete(hash)
      return null
    }
    return row
  }
  async consume(hash: string, now: number): Promise<OidcOP.RefreshToken | null> {
    const row = this.rows.get(hash)
    if (!row) return null
    if (row.exp <= now) {
      this.rows.delete(hash)
      return null
    }
    if (row.consumedAt !== null) return null
    row.consumedAt = now
    this.rows.set(hash, row)
    return row
  }
  async revokeFamily(family_id: string): Promise<void> {
    for (const [k, v] of this.rows) {
      if (v.family_id === family_id) this.rows.delete(k)
    }
  }
}

/** In-memory `AuthOidcOP.IConsentStore`. Keyed by `identityId:clientId` pair. */
export class AuthMemoryConsentStore implements OidcOP.ConsentStore {
  private rows = new Map<string, OidcOP.Consent>()
  private key(identity_id: string, client_id: string) {
    return `${identity_id}:${client_id}`
  }
  async find(identity_id: string, client_id: string): Promise<OidcOP.Consent | null> {
    return this.rows.get(this.key(identity_id, client_id)) ?? null
  }
  async upsert(c: OidcOP.Consent): Promise<void> {
    this.rows.set(this.key(c.identity_id, c.client_id), c)
  }
}
