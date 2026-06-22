/**
 * In-memory stores for the OIDC OP. Suitable for tests and single-instance
 * dev servers. Production deployments wire one of the DB adapters by
 * implementing the same interfaces.
 */

import type { AuthOidcOP } from './types'

export class MemoryClientStore implements AuthOidcOP.IClientStore {
  private rows = new Map<string, AuthOidcOP.IClient>()
  async findById(client_id: string): Promise<AuthOidcOP.IClient | null> {
    return this.rows.get(client_id) ?? null
  }
  async insert(c: AuthOidcOP.IClient): Promise<void> {
    if (this.rows.has(c.client_id)) {
      throw new Error(`MemoryClientStore: client_id '${c.client_id}' already registered`)
    }
    this.rows.set(c.client_id, c)
  }
}

export class AuthMemoryCodeStore implements AuthOidcOP.ICodeStore {
  private rows = new Map<string, AuthOidcOP.ICode>()
  async insert(c: AuthOidcOP.ICode): Promise<void> {
    this.rows.set(c.code, c)
  }
  async consume(code: string, now: number): Promise<AuthOidcOP.ICode | null> {
    const row = this.rows.get(code)
    if (!row) return null
    this.rows.delete(code)
    if (row.exp <= now) return null
    return row
  }
}

export class AuthMemoryAccessTokenStore implements AuthOidcOP.IAccessTokenStore {
  private rows = new Map<string, AuthOidcOP.IAccessToken>()
  async insert(t: AuthOidcOP.IAccessToken): Promise<void> {
    this.rows.set(t.token_hash, t)
  }
  async findByHash(hash: string, now: number): Promise<AuthOidcOP.IAccessToken | null> {
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

export class AuthMemoryRefreshTokenStore implements AuthOidcOP.IRefreshTokenStore {
  private rows = new Map<string, AuthOidcOP.IRefreshToken>()
  async insert(t: AuthOidcOP.IRefreshToken): Promise<void> {
    this.rows.set(t.token_hash, t)
  }
  async findByHash(hash: string, now: number): Promise<AuthOidcOP.IRefreshToken | null> {
    const row = this.rows.get(hash)
    if (!row) return null
    if (row.exp <= now) {
      this.rows.delete(hash)
      return null
    }
    return row
  }
  async consume(hash: string, now: number): Promise<AuthOidcOP.IRefreshToken | null> {
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

export class AuthMemoryConsentStore implements AuthOidcOP.IConsentStore {
  private rows = new Map<string, AuthOidcOP.IConsent>()
  private key(identity_id: string, client_id: string) {
    return `${identity_id}:${client_id}`
  }
  async find(identity_id: string, client_id: string): Promise<AuthOidcOP.IConsent | null> {
    return this.rows.get(this.key(identity_id, client_id)) ?? null
  }
  async upsert(c: AuthOidcOP.IConsent): Promise<void> {
    this.rows.set(this.key(c.identity_id, c.client_id), c)
  }
}
