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
import { AUTH_CREDENTIAL_KINDS } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import type { Identities } from '~/core/identities/identities.types'
import { AUTH_SESSION_KINDS, type Sessions } from '~/core/sessions/sessions.types'

/**
 * Timestamps are timezone-naive DATETIME(3); store UTC and convert at the edges. WARN: MySQL cannot index a
 * JSON path, so the generated columns below carry the uniqueness pg and sqlite index off the column directly.
 */
export const nowMs = sql`CURRENT_TIMESTAMP(3)`

/** SECURITY: opaque keys need a binary collation: the server default folds case and accents, so a
 *  lookup pg and sqlite answer byte-for-byte matched a value it was never given. */
const asciiKey = customType<{ data: string; driverData: string; config: { length: number } }>({
  dataType: (config) => `varchar(${config?.length ?? 64}) character set ascii collate ascii_bin`,
})

/** As {@link asciiKey}, keeping the full charset for values an app, not this library, chooses. */
const binKey = customType<{ data: string; driverData: string; config: { length: number } }>({
  dataType: (config) => `varchar(${config?.length ?? 64}) character set utf8mb4 collate utf8mb4_bin`,
})

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

/** The identity row. Every other table cascades from it. */
export const authIdentities = mysqlTable(
  'auth_identities',
  {
    id: asciiKey('id', { length: 64 }).primaryKey().$defaultFn(authUuidV7),
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
    emailNorm: binKey('email_norm', { length: 320 }).generatedAlwaysAs(sql`(lower(profile ->> '$.email'))`, {
      mode: 'stored',
    }),
    usernameNorm: binKey('username_norm', { length: 191 }).generatedAlwaysAs(sql`(lower(profile ->> '$.username'))`, {
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
    // Bounded here because the norm columns are varchar; checked on all three so the row is refused alike.
    check('chk_auth_identities_email_length', sql`char_length(profile ->> '$.email') <= 320`),
    check('chk_auth_identities_username_length', sql`char_length(profile ->> '$.username') <= 191`),
    // NOTE: full, where pg and sqlite take a partial index; MySQL has none.
    index('auth_identities_deleted_at').on(t.deletedAt),
  ],
)

/**
 * One external login, one row. The unique on the pair is what makes a sub un-stealable: the database
 * refuses the second writer outright, rather than every writer having to check first and hope. A credential
 * kept here, a password, a magic link or a passkey, is an `auth_credentials` row and never one of these.
 */
export const authIdentityProviders = mysqlTable(
  'auth_identity_providers',
  {
    id: asciiKey('id', { length: 64 }).primaryKey().$defaultFn(authUuidV7),
    identityId: asciiKey('identity_id', { length: 64 }).notNull(),
    /** Which party issued the login, namespaced so two of them cannot collide on a shared sub: this is
     *  ours, such as 'oauth:authGoogle' or 'saml:acme', where the sub below is theirs. */
    providerId: binKey('provider_id', { length: 191 }).notNull(),
    /**
     * The issuing party's own stable subject id for the account. NOT NULL: a row without one answers no
     * login. 255 because OIDC caps a `sub` there, while the 191 used elsewhere is the old 767-byte key limit,
     * which DYNAMIC row format is not bound by.
     */
    providerSub: binKey('provider_sub', { length: 255 }).notNull(),
    addedAt: datetime('added_at', { fsp: 3 }).notNull().default(nowMs),
    /** Who attached the login, from the ambient actor. A provider link is a new way to sign in as this
     *  identity, so an admin attaching one and the account holder attaching their own must not read alike.
     *  Null on rows written before the column existed. */
    addedBy: varchar('added_by', { length: 191 }),
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
export const authCredentials = mysqlTable(
  'auth_credentials',
  {
    id: asciiKey('id', { length: 64 }).primaryKey().$defaultFn(authUuidV7),
    identityId: asciiKey('identity_id', { length: 64 }).notNull(),
    /** Which tenant's provider/policy config issued or governs this credential. Scoping only. */
    tenantId: binKey('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull().$type<Credential.Kind>(),
    // 512 fit Argon2id but not a passkey `credential.id`, which WebAuthn allows to ~1364 base64url chars.
    // ASCII keeps 1400 chars at 1400 index bytes, inside InnoDB's 3072-byte key limit.
    secret: asciiKey('secret', { length: 1400 }).notNull(),
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
    /** Carrier for the one-password rule, MySQL having no partial index. NULL elsewhere, and NULLs are
     *  distinct; tenant-scoped because `PasswordsImpl.set` deletes within a tenant.
     *  NOTE: virtual, not stored: MySQL refuses a cascading FK on `identity_id` once a stored column
     *  reads it (error 1215). The unique index below still works, virtual columns being indexable. */
    passwordKey: binKey('password_key', { length: 191 }).generatedAlwaysAs(
      sql`(case when kind = 'password' then concat(identity_id, ':', coalesce(tenant_id, '')) end)`,
      { mode: 'virtual' },
    ),
  },
  (t) => [
    index('auth_credentials_identity_kind').on(t.identityId, t.kind),
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
    // An empty tenant is a scope of its own that matches no global row, so it is refused outright.
    check('chk_auth_credentials_tenant_not_blank', sql`tenant_id IS NULL OR tenant_id <> ''`),
    // `PasswordsImpl.set` already keeps one row by hand; this makes a dropped delete a write error, not a
    // second password that authenticates just as well as the first.
    uniqueIndex('uq_auth_credentials_password').on(t.passwordKey),
    // NOTE: full, where pg and sqlite take `WHERE expires_at IS NOT NULL`; MySQL has no partial index.
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

/** The session row, keyed by the hash of the session id rather than the id itself. */
export const authSessions = mysqlTable(
  'auth_sessions',
  {
    id: asciiKey('id', { length: 64 }).primaryKey(),
    identityId: asciiKey('identity_id', { length: 64 }),
    /** Tenant this session is acting under, drives tenant security policy. Scoping only. */
    tenantId: binKey('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull().$type<Sessions.Kind>(),
    aal: int('aal').notNull().$type<Sessions.AAL>(),
    factors: factorsColumn('factors').notNull().default([]),
    csrfHash: asciiKey('csrf_hash', { length: 128 }),
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
    // WARN: `char_length`, not `length`, because MySQL's `length` counts bytes, so this alone of the three
    // dialects asked a different question the moment a non-ASCII id reached it.
    check('chk_auth_sessions_id_length', sql`char_length(id) = 64`),
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
