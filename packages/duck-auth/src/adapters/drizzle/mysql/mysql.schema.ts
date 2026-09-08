import { sql } from 'drizzle-orm'
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
import type { SqlBridge } from '~/adapters/sql'
import {
  fromJsonColumn,
  parseActingAs,
  parseFactors,
  parseProviders,
  type StoredFactor,
  type StoredProviderLink,
} from '~/adapters/sql/stored-json'
import { AUTH_CREDENTIAL_KINDS, type Credential } from '~/core/credentials/credentials.types'
import { AUTH_SESSION_KINDS, type Sessions } from '~/core/sessions/sessions.types'

/**
 * Timestamps are timezone-naive DATETIME(3); store UTC and convert at the edges.
 *
 * MySQL cannot index a JSON path directly, which is why email and username
 * uniqueness used to be left to the application here while pg and sqlite had
 * real indexes. That is not a weaker guarantee, it is no guarantee: the check
 * is read-then-write, so two concurrent signups both saw a free address and
 * both got it. The generated columns below carry the indexes instead.
 */
const nowMs = sql`CURRENT_TIMESTAMP(3)`

/**
 * JSON columns holding `Date`s. `$type<T>()` is a compile-time assertion and
 * nothing more, so a table whose `providers` column claimed `addedAt: Date` was
 * handing direct `db.select()` callers an ISO string under that name -
 * `addedAt.getTime()` threw, and `addedAt < new Date()` was quietly always
 * `false`. `fromDriver` is the runtime half that makes the claim true. Same SQL
 * type as the column it replaces, so this is not a migration.
 */
const providersColumn = customType<{ data: StoredProviderLink[]; driverData: string }>({
  dataType: () => 'json',
  fromDriver: (value) => parseProviders(fromJsonColumn(value)),
  toDriver: (value) => JSON.stringify(value),
})

const factorsColumn = customType<{ data: StoredFactor[]; driverData: string }>({
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
    id: varchar('id', { length: 64 }).primaryKey(),
    profile: json('profile').notNull().$type<SqlBridge.ProfileMetadataBase>(),
    providers: providersColumn('providers').notNull().default([]),
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
    /**
     * Who soft-deleted the row, from the ambient actor. Cleared by `restore`,
     * so a non-null value and a null `deleted_at` cannot coexist: the pair is
     * read together or not at all.
     */
    deletedBy: varchar('deleted_by', { length: 191 }),
    /**
     * Index carriers for the two uniqueness rules, not part of the row
     * contract - `select()` on this table must exclude them.
     *
     * NULL for a soft-deleted row, which is what reproduces pg's and sqlite's
     * `WHERE deleted_at IS NULL` partial indexes: MySQL allows any number of
     * NULLs in a unique index, so a hidden row drops out of it and frees its
     * address for the grace window, exactly as the other dialects do.
     */
    emailNorm: varchar('email_norm', { length: 320 }).generatedAlwaysAs(
      sql`(if(deleted_at is null, lower(profile ->> '$.email'), null))`,
      { mode: 'stored' },
    ),
    usernameNorm: varchar('username_norm', { length: 191 }).generatedAlwaysAs(
      sql`(if(deleted_at is null, lower(profile ->> '$.username'), null))`,
      { mode: 'stored' },
    ),
  },
  (t) => [
    index('auth_identities_deleted_at').on(t.deletedAt),
    uniqueIndex('uq_auth_identities_email').on(t.emailNorm),
    uniqueIndex('uq_auth_identities_username').on(t.usernameNorm),
    // pg and sqlite have refused a profile missing either key since 5.x; MySQL
    // simply had no equivalent, so the same bad row was writable on one dialect
    // and not the others.
    check(
      'chk_auth_identities_profile_shape',
      sql`profile is null or (profile ->> '$.username' is not null and profile ->> '$.email' is not null)`,
    ),
    check('chk_auth_identities_version', sql`version >= 1`),
  ],
)

export const authCredentials = mysqlTable(
  'auth_credentials',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
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
  },
  (t) => [
    // Compound index covers listByIdentity(id, kind) and listByIdentity(id) both.
    index('auth_credentials_identity_kind').on(t.identityId, t.kind),
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
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
    // SHA-256 hash of the raw session token, text, not the raw token.
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

/** Append-only audit log. Identity FK is SET NULL on hard-delete so the record survives erasure. */
export const authEvents = mysqlTable(
  'auth_events',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    identityId: varchar('identity_id', { length: 64 }),
    sessionId: varchar('session_id', { length: 64 }),
    /** Tenant this event occurred under. Audit/compliance partitioning only. */
    tenantId: varchar('tenant_id', { length: 64 }),
    /** Dot-namespaced event name, e.g. 'login.success', 'mfa.enrolled', 'session.revoked'. */
    event: varchar('event', { length: 128 }).notNull(),
    /** Credential kind that produced the event, when applicable. */
    method: varchar('method', { length: 32 }),
    ip: varchar('ip', { length: 45 }),
    userAgent: text('user_agent'),
    /**
     * Who performed the action, when that differs from `identity_id` - an admin
     * revoking someone else's session, a support agent resetting a password.
     * `identity_id` is the subject; this is the operator.
     */
    actorId: varchar('actor_id', { length: 191 }),
    /** Provider-specific extra fields (error codes, device hints, etc.). */
    metadata: json('metadata').$type<Record<string, unknown> | null>(),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
  },
  (t) => [
    index('auth_events_identity_created').on(t.identityId, t.createdAt),
    index('auth_events_tenant_created').on(t.tenantId, t.createdAt),
    // "Everything operator X did, newest first" - the question `actor_id`
    // exists to answer. `auth_events` is append-only and unbounded, so without
    // this the one query the column was added for is a full scan of the log.
    index('auth_events_actor_created').on(t.actorId, t.createdAt),
    index('auth_events_created').on(t.createdAt),
    check(
      'chk_auth_events_method',
      sql.raw(`method IS NULL OR method IN (${AUTH_CREDENTIAL_KINDS.map((k) => `'${k}'`).join(', ')})`),
    ),
    foreignKey({
      name: 'fk_auth_events_identity',
      columns: [t.identityId],
      foreignColumns: [authIdentities.id],
    }).onDelete('set null'),
  ],
)
