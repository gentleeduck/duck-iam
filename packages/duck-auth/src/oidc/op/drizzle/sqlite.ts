/**
 * SQLite Drizzle stores for the OIDC OP.
 *
 * Mirrors pg.ts column-for-column with sqlite-core types. Suitable for
 * dev / single-instance prod / edge runtimes that ship libsql/turso.
 */

import { and, eq, isNull, lt, or, sql } from 'drizzle-orm'
import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import type { AuthOidcOP } from '../types'

export const authOidcClientsTable = sqliteTable('oidc_clients', {
  clientId: text('client_id').primaryKey(),
  clientSecretHash: text('client_secret_hash'),
  redirectUris: text('redirect_uris').notNull(),
  grantTypes: text('grant_types').notNull(),
  responseTypes: text('response_types').notNull(),
  tokenEndpointAuthMethod: text('token_endpoint_auth_method').notNull(),
  scope: text('scope').notNull(),
  clientName: text('client_name'),
  clientUri: text('client_uri'),
  logoUri: text('logo_uri'),
  createdAt: integer('created_at').notNull(),
})

export const authOidcCodesTable = sqliteTable(
  'oidc_codes',
  {
    code: text('code').primaryKey(),
    clientId: text('client_id').notNull(),
    identityId: text('identity_id').notNull(),
    redirectUri: text('redirect_uri').notNull(),
    scope: text('scope').notNull(),
    nonce: text('nonce'),
    codeChallenge: text('code_challenge'),
    codeChallengeMethod: text('code_challenge_method'),
    tenantId: text('tenant_id'),
    sid: text('sid').notNull(),
    exp: integer('exp').notNull(),
  },
  (t) => [index('oidc_codes_exp').on(t.exp)],
)

export const authOidcAccessTokensTable = sqliteTable(
  'oidc_access_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    clientId: text('client_id').notNull(),
    identityId: text('identity_id').notNull(),
    scope: text('scope').notNull(),
    tenantId: text('tenant_id'),
    exp: integer('exp').notNull(),
  },
  (t) => [index('oidc_at_exp').on(t.exp)],
)

export const authOidcRefreshTokensTable = sqliteTable(
  'oidc_refresh_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    familyId: text('family_id').notNull(),
    clientId: text('client_id').notNull(),
    identityId: text('identity_id').notNull(),
    scope: text('scope').notNull(),
    tenantId: text('tenant_id'),
    exp: integer('exp').notNull(),
    consumedAt: integer('consumed_at'),
  },
  (t) => [index('oidc_rt_family').on(t.familyId), index('oidc_rt_exp').on(t.exp)],
)

export const authOidcConsentsTable = sqliteTable(
  'oidc_consents',
  {
    identityId: text('identity_id').notNull(),
    clientId: text('client_id').notNull(),
    scope: text('scope').notNull(),
    grantedAt: integer('granted_at').notNull(),
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

function isGrantType(v: string): v is AuthOidcOP.IGrantType {
  return v === 'authorization_code' || v === 'refresh_token'
}
function isResponseType(v: string): v is AuthOidcOP.IResponseType {
  return v === 'code'
}
function isTokenAuthMethod(v: string): v is AuthOidcOP.ITokenEndpointAuthMethod {
  return v === 'client_secret_basic' || v === 'client_secret_post' || v === 'none'
}
function isCodeChallengeMethod(v: string): v is AuthOidcOP.ICodeChallengeMethod {
  return v === 'S256' || v === 'plain'
}

function rowToClient(row: typeof authOidcClientsTable.$inferSelect): AuthOidcOP.IClient {
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

function rowToCode(row: typeof authOidcCodesTable.$inferSelect): AuthOidcOP.ICode {
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

function rowToAccess(row: typeof authOidcAccessTokensTable.$inferSelect): AuthOidcOP.IAccessToken {
  return {
    token_hash: row.tokenHash,
    client_id: row.clientId,
    identity_id: row.identityId,
    scope: decodeArray(row.scope),
    tenant_id: row.tenantId,
    exp: row.exp,
  }
}

function rowToRefresh(row: typeof authOidcRefreshTokensTable.$inferSelect): AuthOidcOP.IRefreshToken {
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

function rowToConsent(row: typeof authOidcConsentsTable.$inferSelect): AuthOidcOP.IConsent {
  return {
    identity_id: row.identityId,
    client_id: row.clientId,
    scope: decodeArray(row.scope),
    grantedAt: row.grantedAt,
  }
}

type AnySQLiteDatabase = BaseSQLiteDatabase<'sync' | 'async', unknown, any>

export function authCreateDrizzleSqliteOidcOpStores(db: AnySQLiteDatabase): {
  clients: AuthOidcOP.IClientStore
  codes: AuthOidcOP.ICodeStore
  accessTokens: AuthOidcOP.IAccessTokenStore
  refreshTokens: AuthOidcOP.IRefreshTokenStore
  consents: AuthOidcOP.IConsentStore
} {
  return {
    clients: {
      async findById(client_id) {
        const rows = await db
          .select()
          .from(authOidcClientsTable)
          .where(eq(authOidcClientsTable.clientId, client_id))
          .limit(1)
        const row = rows[0]
        return row ? rowToClient(row) : null
      },
      async insert(c) {
        await db.insert(authOidcClientsTable).values({
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
        await db.insert(authOidcCodesTable).values({
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
        const rows = await db.delete(authOidcCodesTable).where(eq(authOidcCodesTable.code, code)).returning()
        const row = rows[0]
        if (!row) return null
        if (row.exp <= now) return null
        return rowToCode(row)
      },
    },
    accessTokens: {
      async insert(t) {
        await db.insert(authOidcAccessTokensTable).values({
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
          .from(authOidcAccessTokensTable)
          .where(eq(authOidcAccessTokensTable.tokenHash, hash))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (row.exp <= now) {
          await db.delete(authOidcAccessTokensTable).where(eq(authOidcAccessTokensTable.tokenHash, hash))
          return null
        }
        return rowToAccess(row)
      },
      async revokeByHash(hash) {
        await db.delete(authOidcAccessTokensTable).where(eq(authOidcAccessTokensTable.tokenHash, hash))
      },
    },
    refreshTokens: {
      async insert(t) {
        await db.insert(authOidcRefreshTokensTable).values({
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
          .from(authOidcRefreshTokensTable)
          .where(eq(authOidcRefreshTokensTable.tokenHash, hash))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (row.exp <= now) {
          await db.delete(authOidcRefreshTokensTable).where(eq(authOidcRefreshTokensTable.tokenHash, hash))
          return null
        }
        return rowToRefresh(row)
      },
      async consume(hash, now) {
        const updated = await db
          .update(authOidcRefreshTokensTable)
          .set({ consumedAt: now })
          .where(and(eq(authOidcRefreshTokensTable.tokenHash, hash), isNull(authOidcRefreshTokensTable.consumedAt)))
          .returning()
        const row = updated[0]
        if (!row) return null
        if (row.exp <= now) return null
        return rowToRefresh(row)
      },
      async revokeFamily(family_id) {
        await db.delete(authOidcRefreshTokensTable).where(eq(authOidcRefreshTokensTable.familyId, family_id))
      },
    },
    consents: {
      async find(identity_id, client_id) {
        const rows = await db
          .select()
          .from(authOidcConsentsTable)
          .where(and(eq(authOidcConsentsTable.identityId, identity_id), eq(authOidcConsentsTable.clientId, client_id)))
          .limit(1)
        const row = rows[0]
        return row ? rowToConsent(row) : null
      },
      async upsert(c) {
        await db
          .insert(authOidcConsentsTable)
          .values({
            identityId: c.identity_id,
            clientId: c.client_id,
            scope: encodeArray(c.scope),
            grantedAt: c.grantedAt,
          })
          .onConflictDoUpdate({
            target: [authOidcConsentsTable.identityId, authOidcConsentsTable.clientId],
            set: { scope: encodeArray(c.scope), grantedAt: c.grantedAt },
          })
      },
    },
  }
}

export async function authGcDrizzleSqliteOidcOp(db: AnySQLiteDatabase, now: number = Date.now()): Promise<number> {
  const codes = await db
    .delete(authOidcCodesTable)
    .where(lt(authOidcCodesTable.exp, now))
    .returning({ code: authOidcCodesTable.code })
  const access = await db
    .delete(authOidcAccessTokensTable)
    .where(lt(authOidcAccessTokensTable.exp, now))
    .returning({ token_hash: authOidcAccessTokensTable.tokenHash })
  const refresh = await db
    .delete(authOidcRefreshTokensTable)
    .where(or(lt(authOidcRefreshTokensTable.exp, now), sql`${authOidcRefreshTokensTable.consumedAt} IS NOT NULL`))
    .returning({ token_hash: authOidcRefreshTokensTable.tokenHash })
  return codes.length + access.length + refresh.length
}
