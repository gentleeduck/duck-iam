import { relations, sql } from 'drizzle-orm'
import {
  boolean,
  check,
  customType,
  datetime,
  foreignKey,
  index,
  int,
  json,
  mysqlTable,
  text,
  uniqueIndex,
  varchar,
} from 'drizzle-orm/mysql-core'
import { fromJsonColumn, parseActingAs, parseFactors } from '~/adapters/drizzle/drizzle.stored-json'
import { AUTH_CREDENTIAL_KINDS, type Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import type { Identities } from '~/core/identities/identities.types'
import { AUTH_SESSION_KINDS, type Sessions } from '~/core/sessions/sessions.types'

/**
 * Timestamps are timezone-naive DATETIME(3); store UTC and convert at the edges. WARN: MySQL cannot index a
 * JSON path, so the generated columns below carry the uniqueness pg and sqlite index off the column directly.
 */
const nowMs = sql`CURRENT_TIMESTAMP(3)`

const factorsColumn = customType<{ data: Sessions.Factor[]; driverData: string }>({
  dataType: () => 'json',
  fromDriver: (value) => parseFactors(fromJsonColumn(value)),
  toDriver: (value) => JSON.stringify(value),
})

const actingAsColumn = customType<{ data: Sessions.ActingAs | null; driverData: string }>({
  dataType: () => 'json',
  fromDriver: (value) => parseActingAs(fromJsonColumn(value)),
  toDriver: (value) => JSON.stringify(value),
})

export const authIdentities = mysqlTable(
  'auth_identities',
  {
    id: varchar('id', { length: 64 }).primaryKey().$defaultFn(authUuidV7),
    profile: json('profile').notNull().$type<Identities.ProfileMetadataBase>(),
    version: int('version').notNull().default(1),
    emailVerified: boolean('email_verified').notNull().default(false),
    createdBy: varchar('created_by', { length: 191 }),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
    deletedAt: datetime('deleted_at', { fsp: 3 }),
    /** Who soft-deleted the row. Cleared by `restore`, so it is never set while `deleted_at` is null. */
    deletedBy: varchar('deleted_by', { length: 191 }),
    /**
     * Index carriers for the two uniqueness rules, not part of the row contract, so `select()` on this
     * table must exclude them. Unconditional, so a hidden row keeps its address as it does on pg and sqlite.
     */
    emailNorm: varchar('email_norm', { length: 320 }).generatedAlwaysAs(sql`(lower(profile ->> '$.email'))`, {
      mode: 'stored',
    }),
    usernameNorm: varchar('username_norm', { length: 191 }).generatedAlwaysAs(sql`(lower(profile ->> '$.username'))`, {
      mode: 'stored',
    }),
  },
  (t) => [
    uniqueIndex('uq_auth_identities_email').on(t.emailNorm),
    uniqueIndex('uq_auth_identities_username').on(t.usernameNorm),
    // A profile names an account, so both keys must be a string that says something. WARN: coalesced and
    // type-checked, because a CHECK passes on NULL, and MySQL unquotes a JSON null to the text 'null'.
    check(
      'chk_auth_identities_profile_shape',
      sql`coalesce(json_type(json_extract(profile, '$.username')), '') = 'STRING' and coalesce(profile ->> '$.username', '') <> ''
        and coalesce(json_type(json_extract(profile, '$.email')), '') = 'STRING' and coalesce(profile ->> '$.email', '') <> ''`,
    ),
    check('chk_auth_identities_version', sql`version >= 1`),
  ],
)

/**
 * One external login, one row. The unique on the pair is what makes a sub un-stealable: the database
 * refuses the second writer outright, rather than every writer having to check first and hope. A credential
 * kept here - a password, a magic link, a passkey - is a `auth_credentials` row and never one of these.
 */
export const authIdentityProviders = mysqlTable(
  'auth_identity_providers',
  {
    id: varchar('id', { length: 64 }).primaryKey().$defaultFn(authUuidV7),
    identityId: varchar('identity_id', { length: 64 }).notNull(),
    /** Which party issued the login, namespaced so two of them cannot collide on a shared sub: this is
     *  ours - 'oauth:authGoogle', 'saml:acme' - where the sub below is theirs. */
    providerId: varchar('provider_id', { length: 191 }).notNull(),
    /**
     * The issuing party's own stable subject id for the account. NOT NULL: a row without one answers no
     * login. 255 because OIDC caps a `sub` there, while the 191 used elsewhere is the old 767-byte key limit,
     * which DYNAMIC row format is not bound by.
     */
    providerSub: varchar('provider_sub', { length: 255 }).notNull(),
    addedAt: datetime('added_at', { fsp: 3 }).notNull().default(nowMs),
  },
  (t) => [
    // SECURITY: one sub, one row. A hidden row keeps its logins until it is erased, as it keeps its address.
    uniqueIndex('uq_auth_identity_providers_sub').on(t.providerId, t.providerSub),
    // One row per provider: `link` refuses a provider the identity holds, and `unlink` takes no sub, so a
    // second row at the same provider is one nothing could address.
    uniqueIndex('uq_auth_identity_providers_owned').on(t.identityId, t.providerId),
    index('auth_identity_providers_identity').on(t.identityId, t.addedAt),
    // Neither half of the pair may be blank: a blank names nobody, and the pair is what a lookup matches.
    check('chk_auth_identity_providers_provider_not_blank', sql`provider_id <> ''`),
    check('chk_auth_identity_providers_sub_not_blank', sql`provider_sub <> ''`),
    foreignKey({
      name: 'fk_auth_identity_providers_identity',
      columns: [t.identityId],
      foreignColumns: [authIdentities.id],
    }).onDelete('cascade'),
  ],
)

export const authCredentials = mysqlTable(
  'auth_credentials',
  {
    id: varchar('id', { length: 64 }).primaryKey().$defaultFn(authUuidV7),
    identityId: varchar('identity_id', { length: 64 }).notNull(),
    /** Which tenant's provider/policy config issued or governs this credential. Scoping only. */
    tenantId: varchar('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull().$type<Credential.Kind>(),
    // 512 covers Argon2id PHC strings at any sensible cost parameter.
    secret: varchar('secret', { length: 512 }).notNull(),
    metadata: json('metadata').$type<Record<string, unknown> | null>(),
    version: int('version').notNull().default(1),
    createdBy: varchar('created_by', { length: 191 }),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
    lastUsedAt: datetime('last_used_at', { fsp: 3 }),
    expiresAt: datetime('expires_at', { fsp: 3 }),
    revokedAt: datetime('revoked_at', { fsp: 3 }),
    /**
     * Index carriers for the oauth lookup, not part of the row contract, so `select()` on this table must
     * exclude them. MySQL cannot index a JSON path, and MariaDB has no functional index to reach for.
     */
    oauthProvider: varchar('oauth_provider', { length: 191 }).generatedAlwaysAs(sql`(metadata ->> '$.provider')`, {
      mode: 'stored',
    }),
    oauthSub: varchar('oauth_sub', { length: 255 }).generatedAlwaysAs(sql`(metadata ->> '$.sub')`, { mode: 'stored' }),
  },
  (t) => [
    index('auth_credentials_identity_kind').on(t.identityId, t.kind),
    // PERF: `find` reads these two out of `metadata`, so without this every social sign-in scans the table.
    index('auth_credentials_oauth').on(t.oauthProvider, t.oauthSub),
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
    // An empty tenant is a scope of its own that matches no global row, so it is refused outright.
    check('chk_auth_credentials_tenant_not_blank', sql`tenant_id IS NULL OR tenant_id <> ''`),
    index('auth_credentials_expires_at').on(t.expiresAt),
    check('chk_auth_credentials_kind', sql.raw(`kind IN (${AUTH_CREDENTIAL_KINDS.map((k) => `'${k}'`).join(', ')})`)),
    check('chk_auth_credentials_version', sql`version >= 1`),
    check('chk_auth_credentials_secret_not_blank', sql`secret REGEXP '[^[:space:]]'`),
    check('chk_auth_credentials_expires_after_created', sql`expires_at IS NULL OR expires_at >= created_at`),
    check('chk_auth_credentials_revoked_after_created', sql`revoked_at IS NULL OR revoked_at >= created_at`),
    check('chk_auth_credentials_last_used_after_created', sql`last_used_at IS NULL OR last_used_at >= created_at`),
    foreignKey({
      name: 'fk_auth_credentials_identity',
      columns: [t.identityId],
      foreignColumns: [authIdentities.id],
    }).onDelete('cascade'),
  ],
)

export const authSessions = mysqlTable(
  'auth_sessions',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    identityId: varchar('identity_id', { length: 64 }),
    /** Tenant this session is acting under, drives tenant security policy. Scoping only. */
    tenantId: varchar('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull().$type<Sessions.Kind>(),
    aal: int('aal').notNull().$type<Sessions.AAL>(),
    factors: factorsColumn('factors').notNull().default([]),
    csrfHash: varchar('csrf_hash', { length: 128 }),
    ip: varchar('ip', { length: 45 }),
    userAgent: text('user_agent'),
    fingerprint: varchar('fingerprint', { length: 128 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
    rotatedAt: datetime('rotated_at', { fsp: 3 }).notNull(),
    expiresAt: datetime('expires_at', { fsp: 3 }).notNull(),
    absoluteExpiresAt: datetime('absolute_expires_at', { fsp: 3 }).notNull(),
    fresh: boolean('fresh').notNull(),
    actingAs: actingAsColumn('acting_as'),
  },
  (t) => [
    index('auth_sessions_identity').on(t.identityId),
    index('auth_sessions_identity_expires').on(t.identityId, t.expiresAt),
    index('auth_sessions_expires').on(t.expiresAt),
    index('auth_sessions_absolute_expires').on(t.absoluteExpiresAt),
    index('auth_sessions_tenant').on(t.tenantId),
    check('chk_auth_sessions_tenant_not_blank', sql`tenant_id IS NULL OR tenant_id <> ''`),
    check('chk_auth_sessions_kind', sql.raw(`kind IN (${AUTH_SESSION_KINDS.map((k) => `'${k}'`).join(', ')})`)),
    check('chk_auth_sessions_aal', sql`aal BETWEEN 1 AND 3`),
    check('chk_auth_sessions_id_length', sql`length(id) = 64`),
    check('chk_auth_sessions_expires_after_created', sql`expires_at >= created_at`),
    check('chk_auth_sessions_absolute_expires_after_expires', sql`absolute_expires_at >= expires_at`),
    check('chk_auth_sessions_rotated_after_created', sql`rotated_at >= created_at`),
    foreignKey({
      name: 'fk_auth_sessions_identity',
      columns: [t.identityId],
      foreignColumns: [authIdentities.id],
    }).onDelete('cascade'),
  ],
)

/**
 * The schema as drizzle's relational queries read it. Registering these is what lets a caller who passed the
 * schema to `drizzle()` write `db.query.authIdentities.findFirst({ with: { providers: true } })`.
 */
export const authIdentitiesRelations = relations(authIdentities, ({ many }) => ({
  providers: many(authIdentityProviders),
  credentials: many(authCredentials),
  sessions: many(authSessions),
}))

export const authIdentityProvidersRelations = relations(authIdentityProviders, ({ one }) => ({
  identity: one(authIdentities, { fields: [authIdentityProviders.identityId], references: [authIdentities.id] }),
}))

export const authCredentialsRelations = relations(authCredentials, ({ one }) => ({
  identity: one(authIdentities, { fields: [authCredentials.identityId], references: [authIdentities.id] }),
}))

export const authSessionsRelations = relations(authSessions, ({ one }) => ({
  identity: one(authIdentities, { fields: [authSessions.identityId], references: [authIdentities.id] }),
}))

/**
 * Pass this whole object to `drizzle(client, { schema: authMysqlSchema })`. Drizzle keys its relational queries off
 * the object's own names, so spreading this one is what makes `db.query.authIdentities` resolve.
 */
export const authMysqlSchema = {
  authCredentials,
  authCredentialsRelations,
  authIdentities,
  authIdentitiesRelations,
  authIdentityProviders,
  authIdentityProvidersRelations,
  authSessions,
  authSessionsRelations,
}
