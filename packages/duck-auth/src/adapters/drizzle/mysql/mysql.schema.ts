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
import type { SqlBridge } from '~/adapters/sql'
import { AUTH_CREDENTIAL_KINDS, type Credential } from '~/core/credentials/credentials.types'
import type { Identities } from '~/core/identities/identities.types'
import { AUTH_SESSION_KINDS, type Sessions } from '~/core/sessions/sessions.types'

/**
 * Timestamps are timezone-naive DATETIME(3); store UTC and convert at the edges. MySQL
 * can't index a JSON path without a generated column, so email/username uniqueness
 * (unlike pg's expression indexes) is enforced at the application layer for this dialect.
 */
const nowMs = sql`CURRENT_TIMESTAMP(3)`

export const authIdentities = mysqlTable(
  'auth_identities',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    /** Origin/home tenant this identity was created under. Scoping only. */
    tenantId: varchar('tenant_id', { length: 64 }),
    profile: json('profile').notNull().$type<SqlBridge.ProfileMetadataBase>(),
    providers: json('providers').notNull().default([]).$type<Identities.ProviderLink[]>(),
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
  },
  (t) => [
    index('auth_identities_tenant').on(t.tenantId),
    index('auth_identities_deleted_at').on(t.deletedAt),
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
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
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
    factors: json('factors').notNull().default([]).$type<Sessions.Factor[]>(),
    csrfHash: varchar('csrf_hash', { length: 128 }),
    ip: varchar('ip', { length: 45 }),
    userAgent: text('user_agent'),
    fingerprint: varchar('fingerprint', { length: 128 }),
    createdBy: varchar('created_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    rotatedAt: datetime('rotated_at', { fsp: 3 }).notNull(),
    expiresAt: datetime('expires_at', { fsp: 3 }).notNull(),
    absoluteExpiresAt: datetime('absolute_expires_at', { fsp: 3 }).notNull(),
    fresh: boolean('fresh').notNull(),
    actingAs: json('acting_as').$type<Sessions.ActingAs | null>(),
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
    /** Provider-specific extra fields (error codes, device hints, etc.). */
    metadata: json('metadata').$type<Record<string, unknown> | null>(),
    createdBy: varchar('created_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
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
      foreignColumns: [authIdentities.id],
    }).onDelete('set null'),
  ],
)
