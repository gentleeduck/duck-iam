import { relations, sql } from 'drizzle-orm'
import { check, customType, foreignKey, index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import { fromJsonColumn, parseActingAs, parseFactors } from '~/adapters/drizzle/drizzle.stored-json'
import { AUTH_CREDENTIAL_KINDS } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import type { Identities } from '~/core/identities/identities.types'
import { AUTH_SESSION_KINDS, type Sessions } from '~/core/sessions/sessions.types'

/**
 * SQLite has no native jsonb/boolean/timestamptz: `text(..., { mode: 'json' })` stands
 * in for jsonb, booleans are INTEGER 0/1, timestamps are INTEGER unix-ms (store UTC).
 */
// `subsec`, because a bare `unixepoch()` is whole seconds: `findByHashedSecret` orders on this column
// and would pick arbitrarily between two rows minted in the same second. Needs sqlite 3.42.
export const nowMs = sql`(cast(unixepoch('subsec') * 1000 as integer))`

const factorsColumn = customType<{ data: Sessions.Factor[]; driverData: string }>({
  dataType: () => 'text',
  fromDriver: (value) => parseFactors(fromJsonColumn(value)),
  toDriver: (value) => JSON.stringify(value),
})

const actingAsColumn = customType<{ data: Sessions.ActingAs | null; driverData: string }>({
  dataType: () => 'text',
  fromDriver: (value) => parseActingAs(fromJsonColumn(value)),
  toDriver: (value) => JSON.stringify(value),
})

/** The identity row. Every other table cascades from it. */
export const authIdentities = sqliteTable(
  'auth_identities',
  {
    id: text('id').primaryKey().$defaultFn(authUuidV7),
    profile: text('profile', { mode: 'json' }).notNull().$type<Identities.ProfileMetadataBase>(),
    version: integer('version').notNull().default(1),
    emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
    deletedAt: integer('deleted_at', { mode: 'timestamp_ms' }),
    /** Who soft-deleted the row. Cleared by `restore`, so it is never set while `deleted_at` is null. */
    deletedBy: text('deleted_by'),
  },
  (t) => [
    // A profile names an account, so both keys must be a string that says something. WARN: coalesced and
    // type-checked, because a CHECK passes on NULL, and MySQL unquotes a JSON null to the text 'null'.
    check(
      'chk_auth_identities_profile_shape',
      sql`coalesce(json_type(profile, '$.username'), '') = 'text' and coalesce(json_extract(profile, '$.username'), '') <> ''
        and coalesce(json_type(profile, '$.email'), '') = 'text' and coalesce(json_extract(profile, '$.email'), '') <> ''`,
    ),
    // WARN: `->>`, not `json_extract`, because drizzle-kit splits an index expression on commas, and that form
    // emitted DDL for two nonexistent columns and the index silently did not exist.
    // NOTE: full, not partial on `deletedAt`, since a hidden row keeps its address until erased, so nobody can take it.
    uniqueIndex('uq_auth_identities_email').on(sql`(lower(profile ->> '$.email'))`),
    uniqueIndex('uq_auth_identities_username').on(sql`(lower(profile ->> '$.username'))`),
    check('chk_auth_identities_version', sql`version >= 1`),
    // Bounded to match mysql's norm columns, so the row is refused alike on all three.
    check('chk_auth_identities_email_length', sql`length(profile ->> '$.email') <= 320`),
    check('chk_auth_identities_username_length', sql`length(profile ->> '$.username') <= 191`),
    // PERF: only the soft-deleted rows are ever swept, so the live ones stay out of the index.
    index('auth_identities_deleted_at').on(t.deletedAt).where(sql`deleted_at is not null`),
  ],
)

/**
 * One external login, one row. The unique on the pair is what makes a sub un-stealable: the database
 * refuses the second writer outright, rather than every writer having to check first and hope. A credential
 * kept here, a password, a magic link or a passkey, is an `auth_credentials` row and never one of these.
 */
export const authIdentityProviders = sqliteTable(
  'auth_identity_providers',
  {
    id: text('id').primaryKey().$defaultFn(authUuidV7),
    identityId: text('identity_id').notNull(),
    /** Which party issued the login, namespaced so two of them cannot collide on a shared sub: this is
     *  ours, such as 'oauth:authGoogle' or 'saml:acme', where the sub below is theirs. */
    providerId: text('provider_id').notNull(),
    /** The issuing party's own stable subject id for the account. NOT NULL: a row without one answers no
     *  login, and a credential kept here is a `credentials` row, never one of these. */
    providerSub: text('provider_sub').notNull(),
    addedAt: integer('added_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    /** Who attached the login, from the ambient actor. A provider link is a new way to sign in as this
     *  identity, so an admin attaching one and the account holder attaching their own must not read alike.
     *  Null on rows written before the column existed. */
    addedBy: text('added_by'),
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

/** One row per credential: password, passkey, TOTP, api-key and every recovery purpose. */
export const authCredentials = sqliteTable(
  'auth_credentials',
  {
    id: text('id').primaryKey().$defaultFn(authUuidV7),
    identityId: text('identity_id').notNull(),
    /** Which tenant's provider/policy config issued or governs this credential. Scoping only. */
    tenantId: text('tenant_id'),
    kind: text('kind').notNull().$type<Credential.Kind>(),
    secret: text('secret').notNull(),
    metadata: text('metadata', { mode: 'json' }).$type<Record<string, unknown> | null>(),
    version: integer('version').notNull().default(1),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
    lastUsedAt: integer('last_used_at', { mode: 'timestamp_ms' }),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }),
    revokedAt: integer('revoked_at', { mode: 'timestamp_ms' }),
  },
  (t) => [
    index('auth_credentials_identity_kind').on(t.identityId, t.kind),
    // PERF: `find` reads these two out of `metadata`, so without this every social sign-in scans the table.
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
    // An empty tenant is a scope of its own that matches no global row, so it is refused outright.
    check('chk_auth_credentials_tenant_not_blank', sql`tenant_id IS NULL OR tenant_id <> ''`),
    // `PasswordsImpl.set` keeps one row by hand; this turns a dropped delete into a write error. Split in two
    // because a NULL tenant is distinct from every other NULL, so one index cannot bind both scopes.
    uniqueIndex('uq_auth_credentials_password').on(t.identityId).where(sql`kind = 'password' and tenant_id is null`),
    uniqueIndex('uq_auth_credentials_password_tenant')
      .on(t.identityId, t.tenantId)
      .where(sql`kind = 'password' and tenant_id is not null`),
    index('auth_credentials_expires_at').on(t.expiresAt).where(sql`expires_at IS NOT NULL`),
    check('chk_auth_credentials_kind', sql.raw(`kind IN (${AUTH_CREDENTIAL_KINDS.map((k) => `'${k}'`).join(', ')})`)),
    check('chk_auth_credentials_version', sql`version >= 1`),
    check(
      'chk_auth_credentials_secret_not_blank',
      sql`trim(secret, char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> ''`,
    ),
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

/** The session row, keyed by the hash of the session id rather than the id itself. */
export const authSessions = sqliteTable(
  'auth_sessions',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id'),
    /** Tenant this session is acting under, drives tenant security policy. Scoping only. */
    tenantId: text('tenant_id'),
    kind: text('kind').notNull().$type<Sessions.Kind>(),
    aal: integer('aal').notNull().$type<Sessions.AAL>(),
    factors: factorsColumn('factors').notNull().default([]),
    csrfHash: text('csrf_hash'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    fingerprint: text('fingerprint'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
    rotatedAt: integer('rotated_at', { mode: 'timestamp_ms' }).notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
    absoluteExpiresAt: integer('absolute_expires_at', { mode: 'timestamp_ms' }).notNull(),
    fresh: integer('fresh', { mode: 'boolean' }).notNull(),
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

/** Drizzle relations for the query API; the foreign keys themselves live on the tables. */
export const authIdentityProvidersRelations = relations(authIdentityProviders, ({ one }) => ({
  identity: one(authIdentities, { fields: [authIdentityProviders.identityId], references: [authIdentities.id] }),
}))

/** Drizzle relations for the query API; the foreign keys themselves live on the tables. */
export const authCredentialsRelations = relations(authCredentials, ({ one }) => ({
  identity: one(authIdentities, { fields: [authCredentials.identityId], references: [authIdentities.id] }),
}))

/** Drizzle relations for the query API; the foreign keys themselves live on the tables. */
export const authSessionsRelations = relations(authSessions, ({ one }) => ({
  identity: one(authIdentities, { fields: [authSessions.identityId], references: [authIdentities.id] }),
}))

/**
 * Pass this whole object to `drizzle(client, { schema: authSqliteSchema })`. Drizzle keys its relational queries off
 * the object's own names, so spreading this one is what makes `db.query.authIdentities` resolve.
 */
export const authSqliteSchema = {
  authCredentials,
  authCredentialsRelations,
  authIdentities,
  authIdentitiesRelations,
  authIdentityProviders,
  authIdentityProvidersRelations,
  authSessions,
  authSessionsRelations,
}
