CREATE TYPE "public"."iam_combine_algorithm" AS ENUM('deny-overrides', 'allow-overrides', 'first-match', 'highest-priority');--> statement-breakpoint
CREATE TABLE "auth_credentials" (
	"id" uuid PRIMARY KEY NOT NULL,
	"identity_id" uuid NOT NULL,
	"tenant_id" text,
	"kind" text NOT NULL,
	"secret" text NOT NULL,
	"metadata" jsonb,
	"version" integer DEFAULT 1 NOT NULL,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "chk_auth_credentials_tenant_not_blank" CHECK (tenant_id IS NULL OR tenant_id <> ''),
	CONSTRAINT "chk_auth_credentials_kind" CHECK (kind IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key')),
	CONSTRAINT "chk_auth_credentials_version" CHECK (version >= 1),
	CONSTRAINT "chk_auth_credentials_secret_not_blank" CHECK (secret ~ '[^[:space:]]'),
	CONSTRAINT "chk_auth_credentials_expires_after_created" CHECK (expires_at IS NULL OR expires_at >= created_at),
	CONSTRAINT "chk_auth_credentials_revoked_after_created" CHECK (revoked_at IS NULL OR revoked_at >= created_at),
	CONSTRAINT "chk_auth_credentials_last_used_after_created" CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);
--> statement-breakpoint
CREATE TABLE "auth_identities" (
	"id" uuid PRIMARY KEY NOT NULL,
	"profile" jsonb NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	"deleted_by" text,
	CONSTRAINT "chk_auth_identities_profile_shape" CHECK (coalesce(jsonb_typeof(profile->'username'), '') = 'string' and coalesce(profile->>'username', '') <> ''
        and coalesce(jsonb_typeof(profile->'email'), '') = 'string' and coalesce(profile->>'email', '') <> ''),
	CONSTRAINT "chk_auth_identities_version" CHECK (version >= 1),
	CONSTRAINT "chk_auth_identities_email_length" CHECK (length(profile->>'email') <= 320),
	CONSTRAINT "chk_auth_identities_username_length" CHECK (length(profile->>'username') <= 191)
);
--> statement-breakpoint
CREATE TABLE "auth_identity_providers" (
	"id" uuid PRIMARY KEY NOT NULL,
	"identity_id" uuid NOT NULL,
	"provider_id" text NOT NULL,
	"provider_sub" text NOT NULL,
	"added_at" timestamp with time zone DEFAULT now() NOT NULL,
	"added_by" text,
	CONSTRAINT "chk_auth_identity_providers_provider_not_blank" CHECK (provider_id <> ''),
	CONSTRAINT "chk_auth_identity_providers_sub_not_blank" CHECK (provider_sub <> '')
);
--> statement-breakpoint
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
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"rotated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"absolute_expires_at" timestamp with time zone NOT NULL,
	"fresh" boolean NOT NULL,
	"acting_as" jsonb,
	CONSTRAINT "chk_auth_sessions_tenant_not_blank" CHECK (tenant_id IS NULL OR tenant_id <> ''),
	CONSTRAINT "chk_auth_sessions_kind" CHECK (kind IN ('guest', 'user', 'apikey')),
	CONSTRAINT "chk_auth_sessions_aal" CHECK (aal BETWEEN 1 AND 3),
	CONSTRAINT "chk_auth_sessions_id_length" CHECK (length(id) = 64),
	CONSTRAINT "chk_auth_sessions_expires_after_created" CHECK (expires_at >= created_at),
	CONSTRAINT "chk_auth_sessions_absolute_expires_after_expires" CHECK (absolute_expires_at >= expires_at),
	CONSTRAINT "chk_auth_sessions_rotated_after_created" CHECK (rotated_at >= created_at)
);
--> statement-breakpoint
CREATE TABLE "companies" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "iam_assignments" (
	"id" text NOT NULL,
	"subject_id" text NOT NULL,
	"role_id" text NOT NULL,
	"scope" text,
	"starts_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"attributes" jsonb,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pk_iam_assignments" PRIMARY KEY("id"),
	CONSTRAINT "uq_iam_assignments_subject_role_scope" UNIQUE NULLS NOT DISTINCT("subject_id","role_id","scope"),
	CONSTRAINT "ch_iam_assignments_subject_not_blank" CHECK ("iam_assignments"."subject_id" ~ '[^[:space:]]'),
	CONSTRAINT "ch_iam_assignments_scope_not_blank" CHECK ("iam_assignments"."scope" IS NULL OR "iam_assignments"."scope" ~ '[^[:space:]]'),
	CONSTRAINT "ch_iam_assignments_starts_before_expires" CHECK ("iam_assignments"."starts_at" IS NULL OR "iam_assignments"."expires_at" IS NULL OR "iam_assignments"."starts_at" < "iam_assignments"."expires_at")
);
--> statement-breakpoint
CREATE TABLE "iam_policies" (
	"id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"version" integer DEFAULT 1 NOT NULL,
	"algorithm" "iam_combine_algorithm" DEFAULT 'deny-overrides' NOT NULL,
	"rules" jsonb NOT NULL,
	"targets" jsonb,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pk_iam_policies" PRIMARY KEY("id"),
	CONSTRAINT "ch_iam_policies_name_not_blank" CHECK ("iam_policies"."name" ~ '[^[:space:]]'),
	CONSTRAINT "ch_iam_policies_version_positive" CHECK ("iam_policies"."version" >= 1)
);
--> statement-breakpoint
CREATE TABLE "iam_roles" (
	"id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"permissions" jsonb NOT NULL,
	"inherits" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"scope" text,
	"metadata" jsonb,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pk_iam_roles" PRIMARY KEY("id"),
	CONSTRAINT "ch_iam_roles_name_not_blank" CHECK ("iam_roles"."name" ~ '[^[:space:]]'),
	CONSTRAINT "ch_iam_roles_scope_not_blank" CHECK ("iam_roles"."scope" IS NULL OR "iam_roles"."scope" ~ '[^[:space:]]')
);
--> statement-breakpoint
CREATE TABLE "iam_subject_attrs" (
	"subject_id" text NOT NULL,
	"data" jsonb NOT NULL,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pk_iam_subject_attrs" PRIMARY KEY("subject_id"),
	CONSTRAINT "ch_iam_subject_attrs_subject_not_blank" CHECK ("iam_subject_attrs"."subject_id" ~ '[^[:space:]]')
);
--> statement-breakpoint
CREATE TABLE "orders" (
	"id" text PRIMARY KEY NOT NULL,
	"company_id" text NOT NULL,
	"owner_id" uuid NOT NULL,
	"product_id" text NOT NULL,
	"quantity" integer NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "products" (
	"id" text PRIMARY KEY NOT NULL,
	"company_id" text NOT NULL,
	"owner_id" uuid NOT NULL,
	"name" text NOT NULL,
	"price_cents" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"company_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "auth_credentials" ADD CONSTRAINT "fk_auth_credentials_identity" FOREIGN KEY ("identity_id") REFERENCES "public"."auth_identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_identity_providers" ADD CONSTRAINT "fk_auth_identity_providers_identity" FOREIGN KEY ("identity_id") REFERENCES "public"."auth_identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "fk_auth_sessions_identity" FOREIGN KEY ("identity_id") REFERENCES "public"."auth_identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "iam_assignments" ADD CONSTRAINT "fk_iam_assignments_role" FOREIGN KEY ("role_id") REFERENCES "public"."iam_roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "orders" ADD CONSTRAINT "orders_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "orders" ADD CONSTRAINT "orders_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "orders" ADD CONSTRAINT "orders_product_id_products_id_fk" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "products" ADD CONSTRAINT "products_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "products" ADD CONSTRAINT "products_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_id_auth_identities_id_fk" FOREIGN KEY ("id") REFERENCES "public"."auth_identities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "auth_credentials_identity_kind" ON "auth_credentials" USING btree ("identity_id","kind");--> statement-breakpoint
CREATE INDEX "auth_credentials_kind_secret" ON "auth_credentials" USING btree ("kind","secret");--> statement-breakpoint
CREATE INDEX "auth_credentials_tenant" ON "auth_credentials" USING btree ("tenant_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_auth_credentials_password" ON "auth_credentials" USING btree ("identity_id") WHERE kind = 'password' and tenant_id is null;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_auth_credentials_password_tenant" ON "auth_credentials" USING btree ("identity_id","tenant_id") WHERE kind = 'password' and tenant_id is not null;--> statement-breakpoint
CREATE INDEX "auth_credentials_expires_at" ON "auth_credentials" USING btree ("expires_at") WHERE expires_at IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_auth_identities_email" ON "auth_identities" USING btree (((lower(profile->>'email'))));--> statement-breakpoint
CREATE UNIQUE INDEX "uq_auth_identities_username" ON "auth_identities" USING btree (((lower(profile->>'username'))));--> statement-breakpoint
CREATE INDEX "auth_identities_deleted_at" ON "auth_identities" USING btree ("deleted_at") WHERE deleted_at is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_auth_identity_providers_sub" ON "auth_identity_providers" USING btree ("provider_id","provider_sub");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_auth_identity_providers_owned" ON "auth_identity_providers" USING btree ("identity_id","provider_id");--> statement-breakpoint
CREATE INDEX "auth_identity_providers_identity" ON "auth_identity_providers" USING btree ("identity_id","added_at");--> statement-breakpoint
CREATE INDEX "auth_sessions_identity" ON "auth_sessions" USING btree ("identity_id");--> statement-breakpoint
CREATE INDEX "auth_sessions_identity_expires" ON "auth_sessions" USING btree ("identity_id","expires_at");--> statement-breakpoint
CREATE INDEX "auth_sessions_expires" ON "auth_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "auth_sessions_absolute_expires" ON "auth_sessions" USING btree ("absolute_expires_at");--> statement-breakpoint
CREATE INDEX "auth_sessions_tenant" ON "auth_sessions" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "idx_iam_assignments_subject" ON "iam_assignments" USING btree ("subject_id");--> statement-breakpoint
CREATE INDEX "idx_iam_assignments_role" ON "iam_assignments" USING btree ("role_id");--> statement-breakpoint
CREATE INDEX "idx_iam_assignments_subject_scope" ON "iam_assignments" USING btree ("subject_id","scope") WHERE "iam_assignments"."scope" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_iam_assignments_expires_at" ON "iam_assignments" USING btree ("expires_at") WHERE "iam_assignments"."expires_at" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_iam_policies_rules_gin" ON "iam_policies" USING gin ("rules");--> statement-breakpoint
CREATE INDEX "idx_iam_roles_scope" ON "iam_roles" USING btree ("scope") WHERE "iam_roles"."scope" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_iam_roles_permissions_gin" ON "iam_roles" USING gin ("permissions");