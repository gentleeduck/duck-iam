import { sql } from 'drizzle-orm'
import {
  boolean,
  check,
  datetime,
  foreignKey,
  index,
  int,
  json,
  mysqlTable,
  text,
  varchar,
} from 'drizzle-orm/mysql-core'
import { AUTH_CREDENTIAL_KINDS, type Credential, type Identity } from '../../../core/types/identity'
import { AUTH_SESSION_KINDS, type Session } from '../../../core/types/session'
import type { SqlBridge } from '../../sql'

/**
 * @title auth identities table (MySQL / MariaDB)
 * @description Auth identities table. Used to store the identities of users.
 * @note MySQL has native `JSON`, `BOOLEAN` (TINYINT(1)), and `DATETIME(3)`. Drizzle's
 * `json()`/`boolean()`/`datetime({ fsp: 3 })` give the same JS-side ergonomics as pg's
 * jsonb/boolean/timestamptz — `$inferSelect` yields parsed objects, `boolean`, and `Date`.
 * Timestamps are timezone-naive; store UTC and convert at the edges.
 * @note pg's expression unique indexes on `lower(profile->>'email' | 'username')` are
 * omitted here — MySQL cannot index a JSON path without a stored generated column, so
 * email/username uniqueness is enforced at the application layer for this dialect.
 */
export const identitiesTable = mysqlTable(
  'auth_identities',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    /**
     * Origin/home tenant this identity was created under. Scoping only —
     * never used to gate access. Real membership always lives in the host app.
     */
    tenantId: varchar('tenant_id', { length: 64 }),
    profile: json('profile').notNull().$type<SqlBridge.ProfileMetadataBase>(),
    providers: json('providers').notNull().default([]).$type<Identity.ProviderLink[]>(),
    version: int('version').notNull().default(1),
    emailVerified: boolean('email_verified').notNull().default(false),
    createdAt: datetime('created_at', { fsp: 3 }).notNull(),
    updatedAt: datetime('updated_at', { fsp: 3 }).notNull(),
    deletedAt: datetime('deleted_at', { fsp: 3 }),
  },
  (t) => [
    index('auth_identities_tenant').on(t.tenantId),
    index('auth_identities_deleted_at').on(t.deletedAt),
    check('chk_auth_identities_version', sql`version >= 1`),
  ],
)

export const credentialsTable = mysqlTable(
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
    createdAt: datetime('created_at', { fsp: 3 }).notNull(),
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

export const sessionsTable = mysqlTable(
  'auth_sessions',
  {
    // SHA-256 hash of the raw session token — text, not the raw token.
    id: varchar('id', { length: 64 }).primaryKey(),
    identityId: varchar('identity_id', { length: 64 }),
    /** Tenant this session is acting under — drives tenant security policy. Scoping only. */
    tenantId: varchar('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull().$type<Session.Kind>(),
    aal: int('aal').notNull().$type<Session.AAL>(),
    factors: json('factors').notNull().default([]).$type<Session.Factor[]>(),
    csrfHash: varchar('csrf_hash', { length: 128 }),
    ip: varchar('ip', { length: 45 }),
    userAgent: text('user_agent'),
    fingerprint: varchar('fingerprint', { length: 128 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull(),
    rotatedAt: datetime('rotated_at', { fsp: 3 }).notNull(),
    expiresAt: datetime('expires_at', { fsp: 3 }).notNull(),
    absoluteExpiresAt: datetime('absolute_expires_at', { fsp: 3 }).notNull(),
    fresh: boolean('fresh').notNull(),
    actingAs: json('acting_as').$type<Session.ActingAs | null>(),
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
export const eventsTable = mysqlTable(
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
    /** Provider-specific extra fields (error codes, device hints, etc.). */
    metadata: json('metadata').$type<Record<string, unknown> | null>(),
    createdAt: datetime('created_at', { fsp: 3 }).notNull(),
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
