import { Database } from 'bun:sqlite'
import { resolve } from 'node:path'

const dbPath = resolve(import.meta.dir, '../../data.db')
const sqlite = new Database(dbPath)

sqlite.exec('PRAGMA journal_mode = WAL;')

sqlite.exec(`
  CREATE TABLE IF NOT EXISTS auth_identities (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    profile TEXT,
    providers TEXT NOT NULL DEFAULT '[]',
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS auth_identities_tenant ON auth_identities(tenant_id);
  CREATE INDEX IF NOT EXISTS auth_identities_deleted_at ON auth_identities(deleted_at);

  CREATE TABLE IF NOT EXISTS auth_credentials (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    tenant_id TEXT,
    kind TEXT NOT NULL,
    secret TEXT NOT NULL,
    metadata TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER,
    revoked_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS auth_credentials_identity ON auth_credentials(identity_id);
  CREATE INDEX IF NOT EXISTS auth_credentials_kind_secret ON auth_credentials(kind, secret);
  CREATE INDEX IF NOT EXISTS auth_credentials_tenant ON auth_credentials(tenant_id);

  CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    identity_id TEXT,
    tenant_id TEXT,
    kind TEXT NOT NULL,
    aal INTEGER NOT NULL,
    factors TEXT NOT NULL DEFAULT '[]',
    csrf_hash TEXT,
    ip TEXT,
    user_agent TEXT,
    fingerprint TEXT,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    fresh INTEGER NOT NULL,
    acting_as TEXT
  );
  CREATE INDEX IF NOT EXISTS auth_sessions_identity ON auth_sessions(identity_id);
  CREATE INDEX IF NOT EXISTS auth_sessions_expires ON auth_sessions(expires_at);

  CREATE TABLE IF NOT EXISTS access_roles (
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    permissions TEXT NOT NULL,
    inherits TEXT NOT NULL DEFAULT '[]',
    scope TEXT,
    metadata TEXT,
    created_by TEXT,
    updated_by TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    CONSTRAINT pk_access_roles PRIMARY KEY (id),
    CONSTRAINT ch_access_roles_name_not_blank CHECK (length(trim(name)) > 0)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS uq_access_roles_name_scope ON access_roles(name, coalesce(scope, ''));
  CREATE INDEX IF NOT EXISTS idx_access_roles_scope ON access_roles(scope) WHERE scope IS NOT NULL;

  CREATE TABLE IF NOT EXISTS access_policies (
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    algorithm TEXT NOT NULL DEFAULT 'deny-overrides',
    rules TEXT NOT NULL,
    targets TEXT,
    created_by TEXT,
    updated_by TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    CONSTRAINT pk_access_policies PRIMARY KEY (id),
    CONSTRAINT uq_access_policies_name UNIQUE (name),
    CONSTRAINT ch_access_policies_algorithm_valid CHECK (algorithm IN ('deny-overrides','allow-overrides','first-match','highest-priority')),
    CONSTRAINT ch_access_policies_name_not_blank CHECK (length(trim(name)) > 0),
    CONSTRAINT ch_access_policies_version_positive CHECK (version >= 1)
  );

  CREATE TABLE IF NOT EXISTS access_assignments (
    id TEXT,
    subject_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    scope TEXT,
    created_by TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    CONSTRAINT pk_access_assignments PRIMARY KEY (id),
    CONSTRAINT fk_access_assignments_role FOREIGN KEY (role_id) REFERENCES access_roles(id) ON DELETE CASCADE,
    CONSTRAINT ch_access_assignments_subject_not_blank CHECK (length(trim(subject_id)) > 0)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS uq_access_assignments_subject_role_scope ON access_assignments(subject_id, role_id, coalesce(scope, ''));
  CREATE INDEX IF NOT EXISTS idx_access_assignments_subject ON access_assignments(subject_id);
  CREATE INDEX IF NOT EXISTS idx_access_assignments_role ON access_assignments(role_id);
  CREATE INDEX IF NOT EXISTS idx_access_assignments_subject_scope ON access_assignments(subject_id, scope) WHERE scope IS NOT NULL;

  CREATE TABLE IF NOT EXISTS access_subject_attrs (
    subject_id TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_by TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    CONSTRAINT pk_access_subject_attrs PRIMARY KEY (subject_id),
    CONSTRAINT ch_access_subject_attrs_subject_not_blank CHECK (length(trim(subject_id)) > 0)
  );
`)

console.log('Migration complete — data.db ready')
