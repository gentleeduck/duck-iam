/**
 * MySQL Drizzle stores for the OIDC OP. Mirrors pg.ts / sqlite.ts.
 *
 * MySQL note: `text` columns max out at 64 KB and cannot be indexed in
 * full. We index the hash + family_id columns (both fixed-length sha256
 * hex strings) so lookups stay O(log n).
 */

import { and, eq, isNull, lt, or, sql } from 'drizzle-orm'
import type { MySqlDatabase, MySqlQueryResultHKT } from 'drizzle-orm/mysql-core'
import { bigint, index, mysqlTable, text, varchar } from 'drizzle-orm/mysql-core'
import type { OidcOP } from '../types'

export const oidcClientsTable = mysqlTable('oidc_clients', {
  clientId: varchar('client_id', { length: 255 }).primaryKey(),
  clientSecretHash: varchar('client_secret_hash', { length: 64 }),
  redirectUris: text('redirect_uris').notNull(),
  grantTypes: text('grant_types').notNull(),
  responseTypes: text('response_types').notNull(),
  tokenEndpointAuthMethod: varchar('token_endpoint_auth_method', { length: 64 }).notNull(),
  scope: text('scope').notNull(),
  clientName: varchar('client_name', { length: 255 }),
  clientUri: text('client_uri'),
  logoUri: text('logo_uri'),
  createdAt: bigint('created_at', { mode: 'number' }).notNull(),
})

export const oidcCodesTable = mysqlTable(
  'oidc_codes',
  {
    code: varchar('code', { length: 128 }).primaryKey(),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    identityId: varchar('identity_id', { length: 128 }).notNull(),
    redirectUri: text('redirect_uri').notNull(),
    scope: text('scope').notNull(),
    nonce: varchar('nonce', { length: 255 }),
    codeChallenge: varchar('code_challenge', { length: 255 }),
    codeChallengeMethod: varchar('code_challenge_method', { length: 16 }),
    tenantId: varchar('tenant_id', { length: 128 }),
    sid: varchar('sid', { length: 128 }).notNull(),
    exp: bigint('exp', { mode: 'number' }).notNull(),
  },
  (t) => [index('oidc_codes_exp').on(t.exp)],
)

export const oidcAccessTokensTable = mysqlTable(
  'oidc_access_tokens',
  {
    tokenHash: varchar('token_hash', { length: 64 }).primaryKey(),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    identityId: varchar('identity_id', { length: 128 }).notNull(),
    scope: text('scope').notNull(),
    tenantId: varchar('tenant_id', { length: 128 }),
    exp: bigint('exp', { mode: 'number' }).notNull(),
  },
  (t) => [index('oidc_at_exp').on(t.exp)],
)

export const oidcRefreshTokensTable = mysqlTable(
  'oidc_refresh_tokens',
  {
    tokenHash: varchar('token_hash', { length: 64 }).primaryKey(),
    familyId: varchar('family_id', { length: 64 }).notNull(),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    identityId: varchar('identity_id', { length: 128 }).notNull(),
    scope: text('scope').notNull(),
    tenantId: varchar('tenant_id', { length: 128 }),
    exp: bigint('exp', { mode: 'number' }).notNull(),
    consumedAt: bigint('consumed_at', { mode: 'number' }),
  },
  (t) => [index('oidc_rt_family').on(t.familyId), index('oidc_rt_exp').on(t.exp)],
)

export const oidcConsentsTable = mysqlTable(
  'oidc_consents',
  {
    identityId: varchar('identity_id', { length: 128 }).notNull(),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    scope: text('scope').notNull(),
    grantedAt: bigint('granted_at', { mode: 'number' }).notNull(),
  },
  (t) => [index('oidc_consents_id_client').on(t.identityId, t.clientId)],
)

function encodeArray(a: string[]): string {
  return JSON.stringify(a)
}
function decodeArray(s: string): string[] {
  const parsed: unknown = JSON.parse(s)
  if (!Array.isArray(parsed)) return []
  const out: string[] = []
  for (const v of parsed) {
    if (typeof v === 'string') out.push(v)
  }
  return out
}

function isGrantType(v: string): v is OidcOP.IGrantType {
  return v === 'authorization_code' || v === 'refresh_token'
}
function isResponseType(v: string): v is OidcOP.IResponseType {
  return v === 'code'
}
function isTokenAuthMethod(v: string): v is OidcOP.ITokenEndpointAuthMethod {
  return v === 'client_secret_basic' || v === 'client_secret_post' || v === 'none'
}
function isCodeChallengeMethod(v: string): v is OidcOP.ICodeChallengeMethod {
  return v === 'S256' || v === 'plain'
}

function rowToClient(row: typeof oidcClientsTable.$inferSelect): OidcOP.IClient {
  const grantTypes = decodeArray(row.grantTypes).filter(isGrantType)
  const responseTypes = decodeArray(row.responseTypes).filter(isResponseType)
  const tokenAuth = isTokenAuthMethod(row.tokenEndpointAuthMethod) ? row.tokenEndpointAuthMethod : 'none'
  return {
    client_id: row.clientId,
    client_secret_hash: row.clientSecretHash,
    redirect_uris: decodeArray(row.redirectUris),
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: tokenAuth,
    scope: decodeArray(row.scope),
    ...(row.clientName !== null && { client_name: row.clientName }),
    ...(row.clientUri !== null && { client_uri: row.clientUri }),
    ...(row.logoUri !== null && { logo_uri: row.logoUri }),
    createdAt: row.createdAt,
  }
}

function rowToCode(row: typeof oidcCodesTable.$inferSelect): OidcOP.ICode {
  return {
    code: row.code,
    client_id: row.clientId,
    identity_id: row.identityId,
    redirect_uri: row.redirectUri,
    scope: decodeArray(row.scope),
    nonce: row.nonce,
    code_challenge: row.codeChallenge,
    code_challenge_method:
      row.codeChallengeMethod !== null && isCodeChallengeMethod(row.codeChallengeMethod)
        ? row.codeChallengeMethod
        : null,
    tenant_id: row.tenantId,
    sid: row.sid,
    exp: row.exp,
  }
}

function rowToAccess(row: typeof oidcAccessTokensTable.$inferSelect): OidcOP.IAccessToken {
  return {
    token_hash: row.tokenHash,
    client_id: row.clientId,
    identity_id: row.identityId,
    scope: decodeArray(row.scope),
    tenant_id: row.tenantId,
    exp: row.exp,
  }
}

function rowToRefresh(row: typeof oidcRefreshTokensTable.$inferSelect): OidcOP.IRefreshToken {
  return {
    token_hash: row.tokenHash,
    family_id: row.familyId,
    client_id: row.clientId,
    identity_id: row.identityId,
    scope: decodeArray(row.scope),
    tenant_id: row.tenantId,
    exp: row.exp,
    consumedAt: row.consumedAt,
  }
}

function rowToConsent(row: typeof oidcConsentsTable.$inferSelect): OidcOP.IConsent {
  return {
    identity_id: row.identityId,
    client_id: row.clientId,
    scope: decodeArray(row.scope),
    grantedAt: row.grantedAt,
  }
}

// biome-ignore lint/suspicious/noExplicitAny: drizzle schema generic; bound by caller's MySqlDatabase
type AnyMySqlDatabase = MySqlDatabase<MySqlQueryResultHKT, any, any>

/**
 * MySQL note: this adapter uses two SQL statements for `consume` rather
 * than a single `DELETE ... RETURNING` (MySQL lacks RETURNING; we run
 * SELECT then DELETE in a transaction). Net throughput is unchanged for
 * the OP's request volume (codes are single-use, low-rate).
 */
export function createDrizzleMysqlOidcOpStores(db: AnyMySqlDatabase): {
  clients: OidcOP.IClientStore
  codes: OidcOP.ICodeStore
  accessTokens: OidcOP.IAccessTokenStore
  refreshTokens: OidcOP.IRefreshTokenStore
  consents: OidcOP.IConsentStore
} {
  return {
    clients: {
      async findById(client_id) {
        const rows = await db.select().from(oidcClientsTable).where(eq(oidcClientsTable.clientId, client_id)).limit(1)
        const row = rows[0]
        return row ? rowToClient(row) : null
      },
      async insert(c) {
        await db.insert(oidcClientsTable).values({
          clientId: c.client_id,
          clientSecretHash: c.client_secret_hash,
          redirectUris: encodeArray(c.redirect_uris),
          grantTypes: encodeArray(c.grant_types),
          responseTypes: encodeArray(c.response_types),
          tokenEndpointAuthMethod: c.token_endpoint_auth_method,
          scope: encodeArray(c.scope),
          clientName: c.client_name ?? null,
          clientUri: c.client_uri ?? null,
          logoUri: c.logo_uri ?? null,
          createdAt: c.createdAt,
        })
      },
    },
    codes: {
      async insert(c) {
        await db.insert(oidcCodesTable).values({
          code: c.code,
          clientId: c.client_id,
          identityId: c.identity_id,
          redirectUri: c.redirect_uri,
          scope: encodeArray(c.scope),
          nonce: c.nonce,
          codeChallenge: c.code_challenge,
          codeChallengeMethod: c.code_challenge_method,
          tenantId: c.tenant_id,
          sid: c.sid,
          exp: c.exp,
        })
      },
      async consume(code, now) {
        return db.transaction(async (tx) => {
          const rows = await tx.select().from(oidcCodesTable).where(eq(oidcCodesTable.code, code)).limit(1)
          const row = rows[0]
          if (!row) return null
          await tx.delete(oidcCodesTable).where(eq(oidcCodesTable.code, code))
          if (row.exp <= now) return null
          return rowToCode(row)
        })
      },
    },
    accessTokens: {
      async insert(t) {
        await db.insert(oidcAccessTokensTable).values({
          tokenHash: t.token_hash,
          clientId: t.client_id,
          identityId: t.identity_id,
          scope: encodeArray(t.scope),
          tenantId: t.tenant_id,
          exp: t.exp,
        })
      },
      async findByHash(hash, now) {
        const rows = await db
          .select()
          .from(oidcAccessTokensTable)
          .where(eq(oidcAccessTokensTable.tokenHash, hash))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (row.exp <= now) {
          await db.delete(oidcAccessTokensTable).where(eq(oidcAccessTokensTable.tokenHash, hash))
          return null
        }
        return rowToAccess(row)
      },
      async revokeByHash(hash) {
        await db.delete(oidcAccessTokensTable).where(eq(oidcAccessTokensTable.tokenHash, hash))
      },
    },
    refreshTokens: {
      async insert(t) {
        await db.insert(oidcRefreshTokensTable).values({
          tokenHash: t.token_hash,
          familyId: t.family_id,
          clientId: t.client_id,
          identityId: t.identity_id,
          scope: encodeArray(t.scope),
          tenantId: t.tenant_id,
          exp: t.exp,
          consumedAt: t.consumedAt,
        })
      },
      async findByHash(hash, now) {
        const rows = await db
          .select()
          .from(oidcRefreshTokensTable)
          .where(eq(oidcRefreshTokensTable.tokenHash, hash))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (row.exp <= now) {
          await db.delete(oidcRefreshTokensTable).where(eq(oidcRefreshTokensTable.tokenHash, hash))
          return null
        }
        return rowToRefresh(row)
      },
      async consume(hash, now) {
        return db.transaction(async (tx) => {
          const rows = await tx
            .select()
            .from(oidcRefreshTokensTable)
            .where(and(eq(oidcRefreshTokensTable.tokenHash, hash), isNull(oidcRefreshTokensTable.consumedAt)))
            .limit(1)
          const row = rows[0]
          if (!row) return null
          if (row.exp <= now) return null
          await tx
            .update(oidcRefreshTokensTable)
            .set({ consumedAt: now })
            .where(eq(oidcRefreshTokensTable.tokenHash, hash))
          return rowToRefresh({ ...row, consumedAt: now })
        })
      },
      async revokeFamily(family_id) {
        await db.delete(oidcRefreshTokensTable).where(eq(oidcRefreshTokensTable.familyId, family_id))
      },
    },
    consents: {
      async find(identity_id, client_id) {
        const rows = await db
          .select()
          .from(oidcConsentsTable)
          .where(and(eq(oidcConsentsTable.identityId, identity_id), eq(oidcConsentsTable.clientId, client_id)))
          .limit(1)
        const row = rows[0]
        return row ? rowToConsent(row) : null
      },
      async upsert(c) {
        await db
          .insert(oidcConsentsTable)
          .values({
            identityId: c.identity_id,
            clientId: c.client_id,
            scope: encodeArray(c.scope),
            grantedAt: c.grantedAt,
          })
          .onDuplicateKeyUpdate({ set: { scope: encodeArray(c.scope), grantedAt: c.grantedAt } })
      },
    },
  }
}

export async function gcDrizzleMysqlOidcOp(db: AnyMySqlDatabase, now: number = Date.now()): Promise<number> {
  const codes = await db.delete(oidcCodesTable).where(lt(oidcCodesTable.exp, now))
  const access = await db.delete(oidcAccessTokensTable).where(lt(oidcAccessTokensTable.exp, now))
  const refresh = await db
    .delete(oidcRefreshTokensTable)
    .where(or(lt(oidcRefreshTokensTable.exp, now), sql`${oidcRefreshTokensTable.consumedAt} IS NOT NULL`))
  // MySQL Drizzle delete returns affectedRows on the result envelope.
  function rows(r: unknown): number {
    if (typeof r === 'object' && r !== null && 'rowsAffected' in r && typeof r.rowsAffected === 'number') {
      return r.rowsAffected
    }
    if (Array.isArray(r) && typeof r[0]?.affectedRows === 'number') return r[0].affectedRows
    return 0
  }
  return rows(codes) + rows(access) + rows(refresh)
}
