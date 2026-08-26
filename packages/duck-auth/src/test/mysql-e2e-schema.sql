-- Generated from src/adapters/drizzle/mysql/mysql.schema.ts by `bun run e2e:schema`.
-- Applied by the mysql e2e suite so it provisions its own database. Do not hand-edit;
-- regenerate when the drizzle schema changes.
CREATE TABLE `auth_credentials` (
	`id` varchar(64) NOT NULL,
	`identity_id` varchar(64) NOT NULL,
	`tenant_id` varchar(64),
	`kind` varchar(32) NOT NULL,
	`secret` varchar(512) NOT NULL,
	`metadata` json,
	`version` int NOT NULL DEFAULT 1,
	`created_by` varchar(191),
	`updated_by` varchar(191),
	`created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`deleted_at` datetime(3),
	`last_used_at` datetime(3),
	`expires_at` datetime(3),
	`revoked_at` datetime(3),
	CONSTRAINT `auth_credentials_id` PRIMARY KEY(`id`),
	CONSTRAINT `chk_auth_credentials_kind` CHECK(kind IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key')),
	CONSTRAINT `chk_auth_credentials_version` CHECK(version >= 1),
	CONSTRAINT `chk_auth_credentials_secret_not_blank` CHECK(secret REGEXP '[^[:space:]]'),
	CONSTRAINT `chk_auth_credentials_expires_after_created` CHECK(expires_at IS NULL OR expires_at >= created_at),
	CONSTRAINT `chk_auth_credentials_revoked_after_created` CHECK(revoked_at IS NULL OR revoked_at >= created_at),
	CONSTRAINT `chk_auth_credentials_last_used_after_created` CHECK(last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE TABLE `auth_events` (
	`id` varchar(64) NOT NULL,
	`identity_id` varchar(64),
	`session_id` varchar(64),
	`tenant_id` varchar(64),
	`event` varchar(128) NOT NULL,
	`method` varchar(32),
	`ip` varchar(45),
	`user_agent` text,
	`metadata` json,
	`created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	CONSTRAINT `auth_events_id` PRIMARY KEY(`id`),
	CONSTRAINT `chk_auth_events_method` CHECK(method IS NULL OR method IN ('password', 'passkey', 'webauthn-mfa', 'oauth', 'magic-link', 'totp', 'recovery', 'api-key'))
);

CREATE TABLE `auth_identities` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64),
	`profile` json NOT NULL,
	`providers` json NOT NULL DEFAULT ('[]'),
	`version` int NOT NULL DEFAULT 1,
	`email_verified` boolean NOT NULL DEFAULT false,
	`created_by` varchar(191),
	`updated_by` varchar(191),
	`created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`deleted_at` datetime(3),
	CONSTRAINT `auth_identities_id` PRIMARY KEY(`id`),
	CONSTRAINT `chk_auth_identities_version` CHECK(version >= 1)
);

CREATE TABLE `auth_sessions` (
	`id` varchar(64) NOT NULL,
	`identity_id` varchar(64),
	`tenant_id` varchar(64),
	`kind` varchar(32) NOT NULL,
	`aal` int NOT NULL,
	`factors` json NOT NULL DEFAULT ('[]'),
	`csrf_hash` varchar(128),
	`ip` varchar(45),
	`user_agent` text,
	`fingerprint` varchar(128),
	`created_by` varchar(191),
	`updated_by` varchar(191),
	`created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
	`deleted_at` datetime(3),
	`rotated_at` datetime(3) NOT NULL,
	`expires_at` datetime(3) NOT NULL,
	`absolute_expires_at` datetime(3) NOT NULL,
	`fresh` boolean NOT NULL,
	`acting_as` json,
	CONSTRAINT `auth_sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `chk_auth_sessions_kind` CHECK(kind IN ('guest', 'user', 'apikey')),
	CONSTRAINT `chk_auth_sessions_aal` CHECK(aal BETWEEN 1 AND 3),
	CONSTRAINT `chk_auth_sessions_id_length` CHECK(length(id) = 64),
	CONSTRAINT `chk_auth_sessions_expires_after_created` CHECK(expires_at >= created_at),
	CONSTRAINT `chk_auth_sessions_absolute_expires_after_expires` CHECK(absolute_expires_at >= expires_at),
	CONSTRAINT `chk_auth_sessions_rotated_after_created` CHECK(rotated_at >= created_at)
);

ALTER TABLE `auth_credentials` ADD CONSTRAINT `fk_auth_credentials_identity` FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON DELETE cascade ON UPDATE no action;
ALTER TABLE `auth_events` ADD CONSTRAINT `fk_auth_events_identity` FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON DELETE set null ON UPDATE no action;
ALTER TABLE `auth_sessions` ADD CONSTRAINT `fk_auth_sessions_identity` FOREIGN KEY (`identity_id`) REFERENCES `auth_identities`(`id`) ON DELETE cascade ON UPDATE no action;
CREATE INDEX `auth_credentials_identity_kind` ON `auth_credentials` (`identity_id`,`kind`);
CREATE INDEX `auth_credentials_kind_secret` ON `auth_credentials` (`kind`,`secret`);
CREATE INDEX `auth_credentials_tenant` ON `auth_credentials` (`tenant_id`);
CREATE INDEX `auth_credentials_expires_at` ON `auth_credentials` (`expires_at`);
CREATE INDEX `auth_events_identity_created` ON `auth_events` (`identity_id`,`created_at`);
CREATE INDEX `auth_events_tenant_created` ON `auth_events` (`tenant_id`,`created_at`);
CREATE INDEX `auth_events_created` ON `auth_events` (`created_at`);
CREATE INDEX `auth_identities_tenant` ON `auth_identities` (`tenant_id`);
CREATE INDEX `auth_identities_deleted_at` ON `auth_identities` (`deleted_at`);
CREATE INDEX `auth_sessions_identity` ON `auth_sessions` (`identity_id`);
CREATE INDEX `auth_sessions_identity_expires` ON `auth_sessions` (`identity_id`,`expires_at`);
CREATE INDEX `auth_sessions_expires` ON `auth_sessions` (`expires_at`);
CREATE INDEX `auth_sessions_absolute_expires` ON `auth_sessions` (`absolute_expires_at`);
CREATE INDEX `auth_sessions_tenant` ON `auth_sessions` (`tenant_id`);