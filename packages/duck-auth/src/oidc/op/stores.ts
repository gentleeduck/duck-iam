/**
 * In-memory stores for the OIDC OP, for development and test. Production refuses them: each instance holds only
 * the rows it wrote, so a revocation landing on another instance revokes nothing, and a restart forgets every
 * client and grant.
 */

import { isProduction } from '~/core/env'
import { AuthError } from '~/core/errors'
import type { OidcOP } from './types'

/** Throws `AUTH_MISCONFIGURED` in production, naming the store refused. */
function refuseInProduction(store: string): void {
  if (isProduction()) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${store} is refused in production; pass the Drizzle stores from \`@gentleduck/auth/oidc/op/drizzle/{pg,mysql,sqlite}\` as \`stores\``,
    })
  }
}

/** In-memory `OidcOP.ClientStore`. Maps `client_id` → registered client. */
export class AuthMemoryClientStore implements OidcOP.ClientStore {
  private rows = new Map<string, OidcOP.Client>()
  constructor() {
    refuseInProduction('AuthMemoryClientStore')
  }
  async findById(client_id: string): Promise<OidcOP.Client | null> {
    return this.rows.get(client_id) ?? null
  }
  async insert(c: OidcOP.Client): Promise<void> {
    if (this.rows.has(c.client_id)) {
      throw new AuthError('AUTH_ALREADY_EXISTS')
    }
    this.rows.set(c.client_id, c)
  }
}

/** In-memory `OidcOP.CodeStore`. Codes are single-use; `consume` deletes them. */
export class AuthMemoryCodeStore implements OidcOP.CodeStore {
  private rows = new Map<string, OidcOP.Code>()
  constructor() {
    refuseInProduction('AuthMemoryCodeStore')
  }
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

/** In-memory `OidcOP.AccessTokenStore`. Keyed by `token_hash`, revocable by hash or by grant family;
 *  expired tokens evicted lazily on read. */
export class AuthMemoryAccessTokenStore implements OidcOP.AccessTokenStore {
  private rows = new Map<string, OidcOP.AccessToken>()
  constructor() {
    refuseInProduction('AuthMemoryAccessTokenStore')
  }
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
  async revokeFamily(family_id: string): Promise<void> {
    for (const [k, v] of this.rows) {
      if (v.family_id === family_id) this.rows.delete(k)
    }
  }
}

/** In-memory `OidcOP.RefreshTokenStore`. Supports RTR family revocation via `revokeFamily`. */
export class AuthMemoryRefreshTokenStore implements OidcOP.RefreshTokenStore {
  private rows = new Map<string, OidcOP.RefreshToken>()
  constructor() {
    refuseInProduction('AuthMemoryRefreshTokenStore')
  }
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
    return row
  }
  async revokeFamily(family_id: string): Promise<void> {
    for (const [k, v] of this.rows) {
      if (v.family_id === family_id) this.rows.delete(k)
    }
  }
}

/** In-memory `OidcOP.ConsentStore`. Keyed by `identityId:clientId` pair. */
export class AuthMemoryConsentStore implements OidcOP.ConsentStore {
  private rows = new Map<string, OidcOP.Consent>()
  constructor() {
    refuseInProduction('AuthMemoryConsentStore')
  }
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

/** Constructs {@link AuthMemoryClientStore}. */
export function authMemoryClientStore(): AuthMemoryClientStore {
  return new AuthMemoryClientStore()
}

/** Constructs {@link AuthMemoryCodeStore}. */
export function authMemoryCodeStore(): AuthMemoryCodeStore {
  return new AuthMemoryCodeStore()
}

/** Constructs {@link AuthMemoryAccessTokenStore}. */
export function authMemoryAccessTokenStore(): AuthMemoryAccessTokenStore {
  return new AuthMemoryAccessTokenStore()
}

/** Constructs {@link AuthMemoryRefreshTokenStore}. */
export function authMemoryRefreshTokenStore(): AuthMemoryRefreshTokenStore {
  return new AuthMemoryRefreshTokenStore()
}

/** Constructs {@link AuthMemoryConsentStore}. */
export function authMemoryConsentStore(): AuthMemoryConsentStore {
  return new AuthMemoryConsentStore()
}
