/**
 * In-memory stores for the OIDC OP. Suitable for tests and single-instance
 * dev servers. Production deployments wire one of the DB adapters by
 * implementing the same interfaces.
 */

import type { OidcOP } from './types'

export class MemoryClientStore implements OidcOP.IClientStore {
  private rows = new Map<string, OidcOP.IClient>()
  async findById(client_id: string): Promise<OidcOP.IClient | null> {
    return this.rows.get(client_id) ?? null
  }
  async insert(c: OidcOP.IClient): Promise<void> {
    if (this.rows.has(c.client_id)) {
      throw new Error(`MemoryClientStore: client_id '${c.client_id}' already registered`)
    }
    this.rows.set(c.client_id, c)
  }
}

export class MemoryCodeStore implements OidcOP.ICodeStore {
  private rows = new Map<string, OidcOP.ICode>()
  async insert(c: OidcOP.ICode): Promise<void> {
    this.rows.set(c.code, c)
  }
  async consume(code: string, now: number): Promise<OidcOP.ICode | null> {
    const row = this.rows.get(code)
    if (!row) return null
    this.rows.delete(code)
    if (row.exp <= now) return null
    return row
  }
}

export class MemoryAccessTokenStore implements OidcOP.IAccessTokenStore {
  private rows = new Map<string, OidcOP.IAccessToken>()
  async insert(t: OidcOP.IAccessToken): Promise<void> {
    this.rows.set(t.token_hash, t)
  }
  async findByHash(hash: string, now: number): Promise<OidcOP.IAccessToken | null> {
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

export class MemoryRefreshTokenStore implements OidcOP.IRefreshTokenStore {
  private rows = new Map<string, OidcOP.IRefreshToken>()
  async insert(t: OidcOP.IRefreshToken): Promise<void> {
    this.rows.set(t.token_hash, t)
  }
  async findByHash(hash: string, now: number): Promise<OidcOP.IRefreshToken | null> {
    const row = this.rows.get(hash)
    if (!row) return null
    if (row.exp <= now) {
      this.rows.delete(hash)
      return null
    }
    return row
  }
  async consume(hash: string, now: number): Promise<OidcOP.IRefreshToken | null> {
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

export class MemoryConsentStore implements OidcOP.IConsentStore {
  private rows = new Map<string, OidcOP.IConsent>()
  private key(identity_id: string, client_id: string) {
    return `${identity_id}:${client_id}`
  }
  async find(identity_id: string, client_id: string): Promise<OidcOP.IConsent | null> {
    return this.rows.get(this.key(identity_id, client_id)) ?? null
  }
  async upsert(c: OidcOP.IConsent): Promise<void> {
    this.rows.set(this.key(c.identity_id, c.client_id), c)
  }
}
