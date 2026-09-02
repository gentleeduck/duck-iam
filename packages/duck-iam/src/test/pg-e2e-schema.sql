-- PostgreSQL schema for duck-iam e2e suites.
--
-- Hand-kept mirror of `src/adapters/drizzle/pg/pg.schema.ts`. Suites provision
-- their own tables from this file rather than depending on a database someone
-- cloned by hand, which is what makes them runnable anywhere docker is.
-- Constraint naming follows the schema module: pk_ fk_ uq_ idx_ ch_.

DO $$ BEGIN
  CREATE TYPE iam_combine_algorithm AS ENUM ('deny-overrides', 'allow-overrides', 'first-match', 'highest-priority');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS iam_policies (
  id          text NOT NULL,
  name        text NOT NULL,
  description text,
  version     integer NOT NULL DEFAULT 1,
  algorithm   iam_combine_algorithm NOT NULL DEFAULT 'deny-overrides',
  rules       jsonb NOT NULL,
  targets     jsonb,
  created_by  text,
  updated_by  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pk_iam_policies PRIMARY KEY (id),
  CONSTRAINT uq_iam_policies_name UNIQUE (name),
  CONSTRAINT ch_iam_policies_name_not_blank CHECK (name ~ '[^[:space:]]'),
  CONSTRAINT ch_iam_policies_version_positive CHECK (version >= 1)
);
CREATE INDEX IF NOT EXISTS idx_iam_policies_rules_gin ON iam_policies USING gin (rules);

CREATE TABLE IF NOT EXISTS iam_roles (
  id          text NOT NULL,
  name        text NOT NULL,
  description text,
  permissions jsonb NOT NULL,
  inherits    jsonb NOT NULL DEFAULT '[]'::jsonb,
  scope       text,
  metadata    jsonb,
  created_by  text,
  updated_by  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pk_iam_roles PRIMARY KEY (id),
  CONSTRAINT uq_iam_roles_name_scope UNIQUE NULLS NOT DISTINCT (name, scope),
  CONSTRAINT ch_iam_roles_name_not_blank CHECK (name ~ '[^[:space:]]'),
  CONSTRAINT ch_iam_roles_scope_not_blank CHECK (scope IS NULL OR scope ~ '[^[:space:]]')
);
CREATE INDEX IF NOT EXISTS idx_iam_roles_scope ON iam_roles (scope) WHERE scope IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iam_roles_permissions_gin ON iam_roles USING gin (permissions);

CREATE TABLE IF NOT EXISTS iam_assignments (
  id         text NOT NULL,
  subject_id text NOT NULL,
  role_id    text NOT NULL,
  scope      text,
  starts_at  timestamptz,
  expires_at timestamptz,
  attributes jsonb,
  created_by text,
  updated_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pk_iam_assignments PRIMARY KEY (id),
  CONSTRAINT fk_iam_assignments_role FOREIGN KEY (role_id) REFERENCES iam_roles (id) ON DELETE CASCADE,
  CONSTRAINT uq_iam_assignments_subject_role_scope UNIQUE NULLS NOT DISTINCT (subject_id, role_id, scope),
  CONSTRAINT ch_iam_assignments_subject_not_blank CHECK (subject_id ~ '[^[:space:]]'),
  CONSTRAINT ch_iam_assignments_scope_not_blank CHECK (scope IS NULL OR scope ~ '[^[:space:]]'),
  CONSTRAINT ch_iam_assignments_starts_before_expires
    CHECK (starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at)
);
CREATE INDEX IF NOT EXISTS idx_iam_assignments_subject ON iam_assignments (subject_id);
CREATE INDEX IF NOT EXISTS idx_iam_assignments_role ON iam_assignments (role_id);
CREATE INDEX IF NOT EXISTS idx_iam_assignments_subject_scope ON iam_assignments (subject_id, scope) WHERE scope IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iam_assignments_expires_at ON iam_assignments (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS iam_subject_attrs (
  subject_id text NOT NULL,
  data       jsonb NOT NULL,
  created_by text,
  updated_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pk_iam_subject_attrs PRIMARY KEY (subject_id),
  CONSTRAINT ch_iam_subject_attrs_subject_not_blank CHECK (subject_id ~ '[^[:space:]]')
);
