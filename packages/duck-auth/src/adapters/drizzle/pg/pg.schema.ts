import { isNull, sql } from 'drizzle-orm'
import {
  boolean,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core'
import type { SqlBridge } from '~/adapters/sql'
import { AUTH_CREDENTIAL_KINDS, type Credential } from '~/core/credentials/credentials.types'
import type { Identities } from '~/core/identities/identities.types'
import { AUTH_SESSION_KINDS, type Sessions } from '~/core/sessions/sessions.types'

export const authIdentities = pgTable(
  'auth_identities',
  {
    id: uuid('id').primaryKey(),
    profile: jsonb('profile').notNull().$type<SqlBridge.ProfileMetadataBase>(),
    providers: jsonb('providers').notNull().default([]).$type<Identities.ProviderLink[]>(),
    version: integer('version').notNull().default(1),
    emailVerified: boolean('email_verified').notNull().default(false),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
  },
  (t) => [
    check('chk_auth_identities_profile_shape', sql`profile ? 'username' AND profile ? 'email'`),
    index('auth_identities_deleted_at').on(t.deletedAt).where(isNull(t.deletedAt)),
    uniqueIndex('uq_auth_identities_email').on(sql`((lower(profile->>'email')))`).where(isNull(t.deletedAt)),
    uniqueIndex('uq_auth_identities_username').on(sql`((lower(profile->>'username')))`).where(isNull(t.deletedAt)),
    index('auth_identities_providers').using('gin', t.providers),
    check('chk_auth_identities_version', sql`version >= 1`),
  ],
)

export const authCredentials = pgTable(
  'auth_credentials',
  {
    id: uuid('id').primaryKey(),
    identityId: uuid('identity_id').notNull(),
    /** Tenant whose provider/policy config governs this credential. Scoping only. */
    tenantId: text('tenant_id'),
    kind: text('kind').notNull().$type<Credential.Kind>(),
    secret: text('secret').notNull(),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    version: integer('version').notNull().default(1),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [
    // Compound index covers listByIdentity(id, kind) and listByIdentity(id) both
    index('auth_credentials_identity_kind').on(t.identityId, t.kind),
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
    // Partial index for GC: DELETE WHERE expires_at < now()
    index('auth_credentials_expires_at').on(t.expiresAt).where(sql`expires_at IS NOT NULL`),
    check('chk_auth_credentials_kind', sql.raw(`kind IN (${AUTH_CREDENTIAL_KINDS.map((k) => `'${k}'`).join(', ')})`)),
    check('chk_auth_credentials_version', sql`version >= 1`),
    check('chk_auth_credentials_secret_not_blank', sql`secret ~ '[^[:space:]]'`),
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

export const authSessions = pgTable(
  'auth_sessions',
  {
    // SHA-256 hash of the raw session token, kept as text (not a UUID)
    id: text('id').primaryKey(),
    identityId: uuid('identity_id'),
    /** Tenant this session is acting under, drives tenant security policy. Scoping only. */
    tenantId: text('tenant_id'),
    kind: text('kind').notNull().$type<Sessions.Kind>(),
    aal: integer('aal').notNull().$type<Sessions.AAL>(),
    factors: jsonb('factors').notNull().default([]).$type<Sessions.Factor[]>(),
    csrfHash: text('csrf_hash'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    fingerprint: text('fingerprint'),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
    rotatedAt: timestamp('rotated_at', { withTimezone: true }).notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    absoluteExpiresAt: timestamp('absolute_expires_at', { withTimezone: true }).notNull(),
    fresh: boolean('fresh').notNull(),
    actingAs: jsonb('acting_as').$type<Sessions.ActingAs | null>(),
  },
  (t) => [
    // Single-column for deleteAllForIdentity; composite for listActive(identity, expires)
    index('auth_sessions_identity').on(t.identityId),
    index('auth_sessions_identity_expires').on(t.identityId, t.expiresAt),
    index('auth_sessions_expires').on(t.expiresAt),
    index('auth_sessions_absolute_expires').on(t.absoluteExpiresAt),
    index('auth_sessions_tenant').on(t.tenantId),
    check('chk_auth_sessions_kind', sql.raw(`kind IN (${AUTH_SESSION_KINDS.map((k) => `'${k}'`).join(', ')})`)),
    check('chk_auth_sessions_aal', sql`aal BETWEEN 1 AND 3`),
    // SHA-256 hex is always exactly 64 characters
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
export const authEvents = pgTable(
  'auth_events',
  {
    id: uuid('id').primaryKey(),
    identityId: uuid('identity_id'),
    sessionId: text('session_id'),
    /** Tenant this event occurred under. Descriptive only, never drives behavior. */
    tenantId: text('tenant_id'),
    /** Dot-namespaced event name, e.g. 'login.success', 'mfa.enrolled', 'session.revoked'. */
    event: text('event').notNull(),
    /** Credential kind that produced the event, when applicable. */
    method: text('method'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    /** Provider-specific extra fields (error codes, device hints, etc.). */
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Primary query paths: "all events for identity" and "all events in tenant window"
    index('auth_events_identity_created').on(t.identityId, t.createdAt),
    index('auth_events_tenant_created').on(t.tenantId, t.createdAt),
    // GC / retention scans
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
