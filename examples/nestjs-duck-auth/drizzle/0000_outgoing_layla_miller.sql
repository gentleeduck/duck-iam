CREATE TABLE `auth_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`identity_id` text NOT NULL,
	`tenant_id` text,
	`kind` text NOT NULL,
	`secret` text NOT NULL,
	`metadata` text,
	`version` integer DEFAULT 1 NOT NULL,
	`created_by` text,
	`updated_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`last_used_at` integer,
	`expires_at` integer,
	`revoked_at` integer,
	FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "chk_auth_credentials_tenant_not_blank" CHECK(tenant_id IS NULL OR tenant_id <> ''),
	CONSTRAINT "chk_auth_credentials_kind" CHECK(kind IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key')),
	CONSTRAINT "chk_auth_credentials_version" CHECK(version >= 1),
	CONSTRAINT "chk_auth_credentials_secret_not_blank" CHECK(trim(secret, char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> ''),
	CONSTRAINT "chk_auth_credentials_expires_after_created" CHECK(expires_at IS NULL OR expires_at >= created_at),
	CONSTRAINT "chk_auth_credentials_revoked_after_created" CHECK(revoked_at IS NULL OR revoked_at >= created_at),
	CONSTRAINT "chk_auth_credentials_last_used_after_created" CHECK(last_used_at IS NULL OR last_used_at >= created_at)
);
--> statement-breakpoint
CREATE INDEX `auth_credentials_identity_kind` ON `auth_credentials` (`identity_id`,`kind`);--> statement-breakpoint
CREATE INDEX `auth_credentials_oauth` ON `auth_credentials` ((metadata ->> '$.provider'),(metadata ->> '$.sub')) WHERE kind = 'oauth';--> statement-breakpoint
CREATE INDEX `auth_credentials_kind_secret` ON `auth_credentials` (`kind`,`secret`);--> statement-breakpoint
CREATE INDEX `auth_credentials_tenant` ON `auth_credentials` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `auth_credentials_expires_at` ON `auth_credentials` (`expires_at`) WHERE expires_at IS NOT NULL;--> statement-breakpoint
CREATE TABLE `auth_events` (
	`id` text PRIMARY KEY NOT NULL,
	`identity_id` text,
	`session_id` text,
	`tenant_id` text,
	`event` text NOT NULL,
	`method` text,
	`ip` text,
	`user_agent` text,
	`actor_id` text,
	`metadata` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON UPDATE no action ON DELETE set null,
	CONSTRAINT "chk_auth_events_tenant_not_blank" CHECK(tenant_id IS NULL OR tenant_id <> ''),
	CONSTRAINT "chk_auth_events_method" CHECK(method IS NULL OR method IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key'))
);
--> statement-breakpoint
CREATE INDEX `auth_events_identity_created` ON `auth_events` (`identity_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `auth_events_tenant_created` ON `auth_events` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `auth_events_actor_created` ON `auth_events` (`actor_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `auth_events_created` ON `auth_events` (`created_at`);--> statement-breakpoint
CREATE TABLE `auth_identities` (
	`id` text PRIMARY KEY NOT NULL,
	`profile` text NOT NULL,
	`version` integer DEFAULT 1 NOT NULL,
	`email_verified` integer DEFAULT false NOT NULL,
	`created_by` text,
	`updated_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`deleted_at` integer,
	`deleted_by` text,
	CONSTRAINT "chk_auth_identities_profile_shape" CHECK(coalesce(json_type(profile, '$.username'), '') = 'text' and coalesce(json_extract(profile, '$.username'), '') <> ''
        and coalesce(json_type(profile, '$.email'), '') = 'text' and coalesce(json_extract(profile, '$.email'), '') <> ''),
	CONSTRAINT "chk_auth_identities_version" CHECK(version >= 1)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_auth_identities_email` ON `auth_identities` ((lower(profile ->> '$.email')));--> statement-breakpoint
CREATE UNIQUE INDEX `uq_auth_identities_username` ON `auth_identities` ((lower(profile ->> '$.username')));--> statement-breakpoint
CREATE TABLE `auth_identity_providers` (
	`id` text PRIMARY KEY NOT NULL,
	`identity_id` text NOT NULL,
	`provider_id` text NOT NULL,
	`provider_sub` text NOT NULL,
	`added_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "chk_auth_identity_providers_provider_not_blank" CHECK(provider_id <> ''),
	CONSTRAINT "chk_auth_identity_providers_sub_not_blank" CHECK(provider_sub <> '')
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_auth_identity_providers_sub` ON `auth_identity_providers` (`provider_id`,`provider_sub`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_auth_identity_providers_owned` ON `auth_identity_providers` (`identity_id`,`provider_id`);--> statement-breakpoint
CREATE INDEX `auth_identity_providers_identity` ON `auth_identity_providers` (`identity_id`,`added_at`);--> statement-breakpoint
CREATE TABLE `auth_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`identity_id` text,
	`tenant_id` text,
	`kind` text NOT NULL,
	`aal` integer NOT NULL,
	`factors` text DEFAULT '[]' NOT NULL,
	`csrf_hash` text,
	`ip` text,
	`user_agent` text,
	`fingerprint` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`rotated_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`absolute_expires_at` integer NOT NULL,
	`fresh` integer NOT NULL,
	`acting_as` text,
	FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "chk_auth_sessions_tenant_not_blank" CHECK(tenant_id IS NULL OR tenant_id <> ''),
	CONSTRAINT "chk_auth_sessions_kind" CHECK(kind IN ('guest', 'user', 'apikey')),
	CONSTRAINT "chk_auth_sessions_aal" CHECK(aal BETWEEN 1 AND 3),
	CONSTRAINT "chk_auth_sessions_id_length" CHECK(length(id) = 64),
	CONSTRAINT "chk_auth_sessions_expires_after_created" CHECK(expires_at >= created_at),
	CONSTRAINT "chk_auth_sessions_absolute_expires_after_expires" CHECK(absolute_expires_at >= expires_at),
	CONSTRAINT "chk_auth_sessions_rotated_after_created" CHECK(rotated_at >= created_at)
);
--> statement-breakpoint
CREATE INDEX `auth_sessions_identity` ON `auth_sessions` (`identity_id`);--> statement-breakpoint
CREATE INDEX `auth_sessions_identity_expires` ON `auth_sessions` (`identity_id`,`expires_at`);--> statement-breakpoint
CREATE INDEX `auth_sessions_expires` ON `auth_sessions` (`expires_at`);--> statement-breakpoint
CREATE INDEX `auth_sessions_absolute_expires` ON `auth_sessions` (`absolute_expires_at`);--> statement-breakpoint
CREATE INDEX `auth_sessions_tenant` ON `auth_sessions` (`tenant_id`);--> statement-breakpoint
CREATE TABLE `iam_assignments` (
	`id` text PRIMARY KEY NOT NULL,
	`subject_id` text NOT NULL,
	`role_id` text NOT NULL,
	`scope` text,
	`starts_at` integer,
	`expires_at` integer,
	`attributes` text,
	`created_by` text,
	`updated_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`role_id`) REFERENCES `iam_roles`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "ch_iam_assignments_subject_not_blank" CHECK(trim("iam_assignments"."subject_id", char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> ''),
	CONSTRAINT "ch_iam_assignments_scope_not_blank" CHECK("iam_assignments"."scope" IS NULL OR trim("iam_assignments"."scope", char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> ''),
	CONSTRAINT "ch_iam_assignments_starts_before_expires" CHECK("iam_assignments"."starts_at" IS NULL OR "iam_assignments"."expires_at" IS NULL OR "iam_assignments"."starts_at" < "iam_assignments"."expires_at")
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_iam_assignments_subject_role_scope` ON `iam_assignments` (`subject_id`,`role_id`,`scope`) WHERE "iam_assignments"."scope" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_iam_assignments_subject_role_global` ON `iam_assignments` (`subject_id`,`role_id`) WHERE "iam_assignments"."scope" IS NULL;--> statement-breakpoint
CREATE INDEX `idx_iam_assignments_subject` ON `iam_assignments` (`subject_id`);--> statement-breakpoint
CREATE INDEX `idx_iam_assignments_role` ON `iam_assignments` (`role_id`);--> statement-breakpoint
CREATE INDEX `idx_iam_assignments_subject_scope` ON `iam_assignments` (`subject_id`,`scope`) WHERE "iam_assignments"."scope" IS NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_iam_assignments_expires_at` ON `iam_assignments` (`expires_at`) WHERE "iam_assignments"."expires_at" IS NOT NULL;--> statement-breakpoint
CREATE TABLE `iam_policies` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`description` text,
	`version` integer DEFAULT 1 NOT NULL,
	`algorithm` text DEFAULT 'deny-overrides' NOT NULL,
	`rules` text NOT NULL,
	`targets` text,
	`created_by` text,
	`updated_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	CONSTRAINT "ch_iam_policies_algorithm_valid" CHECK("iam_policies"."algorithm" IN ('deny-overrides','allow-overrides','first-match','highest-priority')),
	CONSTRAINT "ch_iam_policies_name_not_blank" CHECK(trim("iam_policies"."name", char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> ''),
	CONSTRAINT "ch_iam_policies_version_positive" CHECK("iam_policies"."version" >= 1)
);
--> statement-breakpoint
CREATE TABLE `iam_roles` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`description` text,
	`permissions` text NOT NULL,
	`inherits` text DEFAULT '[]' NOT NULL,
	`scope` text,
	`metadata` text,
	`created_by` text,
	`updated_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	CONSTRAINT "ch_iam_roles_name_not_blank" CHECK(trim("iam_roles"."name", char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> ''),
	CONSTRAINT "ch_iam_roles_scope_not_blank" CHECK("iam_roles"."scope" IS NULL OR trim("iam_roles"."scope", char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> '')
);
--> statement-breakpoint
CREATE INDEX `idx_iam_roles_scope` ON `iam_roles` (`scope`) WHERE "iam_roles"."scope" IS NOT NULL;--> statement-breakpoint
CREATE TABLE `iam_subject_attrs` (
	`subject_id` text PRIMARY KEY NOT NULL,
	`data` text NOT NULL,
	`created_by` text,
	`updated_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	CONSTRAINT "ch_iam_subject_attrs_subject_not_blank" CHECK(trim("iam_subject_attrs"."subject_id", char(32) || char(9) || char(10) || char(11) || char(12) || char(13)) <> '')
);
