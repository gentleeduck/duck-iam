import { isNull, sql } from 'drizzle-orm'
import { check, foreignKey, index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import type { SqlBridge } from '~/adapters/sql'
import type { Identity } from '~/core/identities/identities.types'
import { AUTH_SESSION_KINDS, type Session } from '~/core/sessions/sessions.types'
import { AUTH_CREDENTIAL_KINDS, type Credential } from '~/core/types/identity'

/**
 * @title auth identities table (SQLite)
 * @description Auth identities table. Used to store the identities of users.
 * @note SQLite has no native jsonb/boolean/timestamptz. `text(..., { mode: 'json' })`
 * gives JS-side object ergonomics like pg's jsonb; booleans are INTEGER 0/1;
 * timestamps are INTEGER unix-ms, timezone-naive (store UTC, convert at the edges).
 */
export const identitiesTable = sqliteTable(
  'auth_identities',
  {
    id: text('id').primaryKey(),
    profile: text('profile', { mode: 'json' }).notNull().$type<SqlBridge.ProfileMetadataBase>(),
    providers: text('providers', { mode: 'json' }).notNull().default('[]').$type<Identity.ProviderLink[]>(),
    version: integer('version').notNull().default(1),
    emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
    deletedAt: integer('deleted_at', { mode: 'timestamp_ms' }),
  },
  (t) => [
    // pg's `profile ? 'key'` returns NULL (constraint-passes) on a NULL profile;
    // mirrored explicitly here since json_extract(NULL, ...) IS NOT NULL is FALSE, not NULL.
    check(
      'chk_auth_identities_profile_shape',
      sql`profile is null or (
        json_extract(profile, '$.username') is not null
        and json_extract(profile, '$.email') is not null
      )`,
    ),
    index('auth_identities_deleted_at').on(t.deletedAt).where(isNull(t.deletedAt)),
    uniqueIndex('uq_auth_identities_email')
      .on(sql`(lower(json_extract(profile, '$.email')))`)
      .where(isNull(t.deletedAt)),
    uniqueIndex('uq_auth_identities_username')
      .on(sql`(lower(json_extract(profile, '$.username')))`)
      .where(isNull(t.deletedAt)),
    check('chk_auth_identities_version', sql`version >= 1`),
  ],
)

export const credentialsTable = sqliteTable(
  'auth_credentials',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id').notNull(),
    /** Which tenant's provider/policy config issued or governs this credential. Scoping only. */
    tenantId: text('tenant_id'),
    kind: text('kind').notNull().$type<Credential.Kind>(),
    secret: text('secret').notNull(),
    metadata: text('metadata', { mode: 'json' }).$type<Record<string, unknown> | null>(),
    version: integer('version').notNull().default(1),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    lastUsedAt: integer('last_used_at', { mode: 'timestamp_ms' }),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }),
    revokedAt: integer('revoked_at', { mode: 'timestamp_ms' }),
  },
  (t) => [
    // Compound index covers listByIdentity(id, kind) and listByIdentity(id) both.
    index('auth_credentials_identity_kind').on(t.identityId, t.kind),
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
    index('auth_credentials_expires_at').on(t.expiresAt).where(sql`expires_at IS NOT NULL`),
    check('chk_auth_credentials_kind', sql.raw(`kind IN (${AUTH_CREDENTIAL_KINDS.map((k) => `'${k}'`).join(', ')})`)),
    check('chk_auth_credentials_version', sql`version >= 1`),
    check('chk_auth_credentials_secret_not_blank', sql`length(trim(secret)) > 0`),
    check('chk_auth_credentials_expires_after_created', sql`expires_at IS NULL OR expires_at >= created_at`),
    check('chk_auth_credentials_revoked_after_created', sql`revoked_at IS NULL OR revoked_at >= created_at`),
    check('chk_auth_credentials_last_used_after_created', sql`last_used_at IS NULL OR last_used_at >= created_at`),
    foreignKey({
      name: 'fk_auth_credentials_identity',
      columns: [t.identityId],
      foreignColumns: [identitiesTable.id],
    }).onDelete('cascade'),
  ],
)

export const sessionsTable = sqliteTable(
  'auth_sessions',
  {
    // SHA-256 hash of the raw session token — text, not the raw token.
    id: text('id').primaryKey(),
    identityId: text('identity_id'),
    /** Tenant this session is acting under — drives tenant security policy. Scoping only. */
    tenantId: text('tenant_id'),
    kind: text('kind').notNull().$type<Session.Kind>(),
    aal: integer('aal').notNull().$type<Session.AAL>(),
    factors: text('factors', { mode: 'json' }).notNull().default('[]').$type<Session.Factor[]>(),
    csrfHash: text('csrf_hash'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    fingerprint: text('fingerprint'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    rotatedAt: integer('rotated_at', { mode: 'timestamp_ms' }).notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
    absoluteExpiresAt: integer('absolute_expires_at', { mode: 'timestamp_ms' }).notNull(),
    fresh: integer('fresh', { mode: 'boolean' }).notNull(),
    actingAs: text('acting_as', { mode: 'json' }).$type<Session.ActingAs | null>(),
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
      foreignColumns: [identitiesTable.id],
    }).onDelete('cascade'),
  ],
)

/**
 * Append-only audit log. Never UPDATE or DELETE rows (except compliance-driven
 * purge). Identity FK is SET NULL on hard-delete so the event record survives
 * erasure. Schema-parity with pg — not yet wired into the bridge (same open
 * gap as the pg adapter; wire both together once `SqlBridge.Me` defines
 * an `events` section).
 */
export const eventsTable = sqliteTable(
  'auth_events',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id'),
    sessionId: text('session_id'),
    /** Tenant this event occurred under. Audit/compliance partitioning only. */
    tenantId: text('tenant_id'),
    /** Dot-namespaced event name, e.g. 'login.success', 'mfa.enrolled', 'session.revoked'. */
    event: text('event').notNull(),
    /** Credential kind that produced the event, when applicable. */
    method: text('method'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    /** Provider-specific extra fields (error codes, device hints, etc.). */
    metadata: text('metadata', { mode: 'json' }).$type<Record<string, unknown> | null>(),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  },
  (t) => [
    index('auth_events_identity_created').on(t.identityId, t.createdAt),
    index('auth_events_tenant_created').on(t.tenantId, t.createdAt),
    index('auth_events_created').on(t.createdAt),
    check(
      'chk_auth_events_method',
      sql.raw(`method IS NULL OR method IN (${AUTH_CREDENTIAL_KINDS.map((k) => `'${k}'`).join(', ')})`),
    ),
    foreignKey({
      name: 'fk_auth_events_identity',
      columns: [t.identityId],
      foreignColumns: [identitiesTable.id],
    }).onDelete('set null'),
  ],
)
