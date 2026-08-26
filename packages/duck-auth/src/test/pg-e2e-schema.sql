-- Generated from src/adapters/drizzle/pg/pg.schema.ts by `bun run e2e:schema`.
-- Applied by the pg e2e suite so it provisions its own database. Do not hand-edit;
-- regenerate when the drizzle schema changes.
CREATE TABLE "auth_credentials" (
	"id" uuid PRIMARY KEY NOT NULL,
	"identity_id" uuid NOT NULL,
	"tenant_id" text,
	"kind" text NOT NULL,
	"secret" text NOT NULL,
	"metadata" jsonb,
	"version" integer DEFAULT 1 NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "chk_auth_credentials_kind" CHECK (kind IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key')),
	CONSTRAINT "chk_auth_credentials_version" CHECK (version >= 1),
	CONSTRAINT "chk_auth_credentials_secret_not_blank" CHECK (secret ~ '[^[:space:]]'),
	CONSTRAINT "chk_auth_credentials_expires_after_created" CHECK (expires_at IS NULL OR expires_at >= created_at),
	CONSTRAINT "chk_auth_credentials_revoked_after_created" CHECK (revoked_at IS NULL OR revoked_at >= created_at),
	CONSTRAINT "chk_auth_credentials_last_used_after_created" CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE TABLE "auth_events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"identity_id" uuid,
	"session_id" text,
	"tenant_id" text,
	"event" text NOT NULL,
	"method" text,
	"ip" text,
	"user_agent" text,
	"metadata" jsonb,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "chk_auth_events_method" CHECK (method IS NULL OR method IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key'))
);

CREATE TABLE "auth_identities" (
	"id" uuid PRIMARY KEY NOT NULL,
	"profile" jsonb NOT NULL,
	"providers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "chk_auth_identities_profile_shape" CHECK (profile ? 'username' AND profile ? 'email'),
	CONSTRAINT "chk_auth_identities_version" CHECK (version >= 1)
);

CREATE TABLE "auth_sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"identity_id" uuid,
	"tenant_id" text,
	"kind" text NOT NULL,
	"aal" integer NOT NULL,
	"factors" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"csrf_hash" text,
	"ip" text,
	"user_agent" text,
	"fingerprint" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"rotated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"absolute_expires_at" timestamp with time zone NOT NULL,
	"fresh" boolean NOT NULL,
	"acting_as" jsonb,
	CONSTRAINT "chk_auth_sessions_kind" CHECK (kind IN ('guest', 'user', 'apikey')),
	CONSTRAINT "chk_auth_sessions_aal" CHECK (aal BETWEEN 1 AND 3),
	CONSTRAINT "chk_auth_sessions_id_length" CHECK (length(id) = 64),
	CONSTRAINT "chk_auth_sessions_expires_after_created" CHECK (expires_at >= created_at),
	CONSTRAINT "chk_auth_sessions_absolute_expires_after_expires" CHECK (absolute_expires_at >= expires_at),
	CONSTRAINT "chk_auth_sessions_rotated_after_created" CHECK (rotated_at >= created_at)
);

ALTER TABLE "auth_credentials" ADD CONSTRAINT "fk_auth_credentials_identity" FOREIGN KEY ("identity_id") REFERENCES "public"."auth_identities"("id") ON DELETE cascade ON UPDATE no action;
ALTER TABLE "auth_events" ADD CONSTRAINT "fk_auth_events_identity" FOREIGN KEY ("identity_id") REFERENCES "public"."auth_identities"("id") ON DELETE set null ON UPDATE no action;
ALTER TABLE "auth_sessions" ADD CONSTRAINT "fk_auth_sessions_identity" FOREIGN KEY ("identity_id") REFERENCES "public"."auth_identities"("id") ON DELETE cascade ON UPDATE no action;
CREATE INDEX "auth_credentials_identity_kind" ON "auth_credentials" USING btree ("identity_id","kind");
CREATE INDEX "auth_credentials_kind_secret" ON "auth_credentials" USING btree ("kind","secret");
CREATE INDEX "auth_credentials_tenant" ON "auth_credentials" USING btree ("tenant_id");
CREATE INDEX "auth_credentials_expires_at" ON "auth_credentials" USING btree ("expires_at") WHERE expires_at IS NOT NULL;
CREATE INDEX "auth_events_identity_created" ON "auth_events" USING btree ("identity_id","created_at");
CREATE INDEX "auth_events_tenant_created" ON "auth_events" USING btree ("tenant_id","created_at");
CREATE INDEX "auth_events_created" ON "auth_events" USING btree ("created_at");
CREATE INDEX "auth_identities_deleted_at" ON "auth_identities" USING btree ("deleted_at") WHERE "auth_identities"."deleted_at" is null;
CREATE UNIQUE INDEX "uq_auth_identities_email" ON "auth_identities" USING btree (((lower(profile->>'email')))) WHERE "auth_identities"."deleted_at" is null;
CREATE UNIQUE INDEX "uq_auth_identities_username" ON "auth_identities" USING btree (((lower(profile->>'username')))) WHERE "auth_identities"."deleted_at" is null;
CREATE INDEX "auth_identities_providers" ON "auth_identities" USING gin ("providers");
CREATE INDEX "auth_sessions_identity" ON "auth_sessions" USING btree ("identity_id");
CREATE INDEX "auth_sessions_identity_expires" ON "auth_sessions" USING btree ("identity_id","expires_at");
CREATE INDEX "auth_sessions_expires" ON "auth_sessions" USING btree ("expires_at");
CREATE INDEX "auth_sessions_absolute_expires" ON "auth_sessions" USING btree ("absolute_expires_at");
CREATE INDEX "auth_sessions_tenant" ON "auth_sessions" USING btree ("tenant_id");