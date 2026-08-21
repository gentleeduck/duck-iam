-- Generated from src/oidc/op/drizzle/mysql.ts by `bun run e2e:schema`.
-- Applied by the OIDC OP e2e suites. Do not hand-edit; regenerate when the
-- drizzle schema changes.
CREATE TABLE `oidc_access_tokens` (
	`token_hash` varchar(64) NOT NULL,
	`client_id` varchar(255) NOT NULL,
	`identity_id` varchar(128) NOT NULL,
	`scope` text NOT NULL,
	`tenant_id` varchar(128),
	`exp` bigint NOT NULL,
	CONSTRAINT `oidc_access_tokens_token_hash` PRIMARY KEY(`token_hash`)
);

CREATE TABLE `oidc_clients` (
	`client_id` varchar(255) NOT NULL,
	`client_secret_hash` varchar(64),
	`redirect_uris` text NOT NULL,
	`grant_types` text NOT NULL,
	`response_types` text NOT NULL,
	`token_endpoint_auth_method` varchar(64) NOT NULL,
	`scope` text NOT NULL,
	`client_name` varchar(255),
	`client_uri` text,
	`logo_uri` text,
	`created_at` bigint NOT NULL,
	CONSTRAINT `oidc_clients_client_id` PRIMARY KEY(`client_id`)
);

CREATE TABLE `oidc_codes` (
	`code` varchar(128) NOT NULL,
	`client_id` varchar(255) NOT NULL,
	`identity_id` varchar(128) NOT NULL,
	`redirect_uri` text NOT NULL,
	`scope` text NOT NULL,
	`nonce` varchar(255),
	`code_challenge` varchar(255),
	`code_challenge_method` varchar(16),
	`tenant_id` varchar(128),
	`sid` varchar(128) NOT NULL,
	`exp` bigint NOT NULL,
	CONSTRAINT `oidc_codes_code` PRIMARY KEY(`code`)
);

CREATE TABLE `oidc_consents` (
	`identity_id` varchar(128) NOT NULL,
	`client_id` varchar(255) NOT NULL,
	`scope` text NOT NULL,
	`granted_at` bigint NOT NULL,
	CONSTRAINT `oidc_consents_id_client` UNIQUE(`identity_id`,`client_id`)
);

CREATE TABLE `oidc_refresh_tokens` (
	`token_hash` varchar(64) NOT NULL,
	`family_id` varchar(64) NOT NULL,
	`client_id` varchar(255) NOT NULL,
	`identity_id` varchar(128) NOT NULL,
	`scope` text NOT NULL,
	`tenant_id` varchar(128),
	`exp` bigint NOT NULL,
	`consumed_at` bigint,
	CONSTRAINT `oidc_refresh_tokens_token_hash` PRIMARY KEY(`token_hash`)
);

CREATE INDEX `oidc_at_exp` ON `oidc_access_tokens` (`exp`);
CREATE INDEX `oidc_codes_exp` ON `oidc_codes` (`exp`);
CREATE INDEX `oidc_rt_family` ON `oidc_refresh_tokens` (`family_id`);
CREATE INDEX `oidc_rt_exp` ON `oidc_refresh_tokens` (`exp`);