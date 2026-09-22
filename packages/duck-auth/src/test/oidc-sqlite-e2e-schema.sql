-- Generated from src/oidc/op/drizzle/sqlite.ts by `bun run e2e:schema`.
-- Applied by the OIDC OP e2e suites. Do not hand-edit; regenerate when the
-- drizzle schema changes.
CREATE TABLE `oidc_access_tokens` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`identity_id` text NOT NULL,
	`scope` text NOT NULL,
	`tenant_id` text,
	`exp` integer NOT NULL
);

CREATE INDEX `oidc_at_exp` ON `oidc_access_tokens` (`exp`);
CREATE TABLE `oidc_clients` (
	`client_id` text PRIMARY KEY NOT NULL,
	`client_secret_hash` text,
	`redirect_uris` text NOT NULL,
	`grant_types` text NOT NULL,
	`response_types` text NOT NULL,
	`token_endpoint_auth_method` text NOT NULL,
	`scope` text NOT NULL,
	`client_name` text,
	`client_uri` text,
	`logo_uri` text,
	`created_at` integer NOT NULL
);

CREATE TABLE `oidc_codes` (
	`code` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`identity_id` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`scope` text NOT NULL,
	`nonce` text,
	`code_challenge` text,
	`code_challenge_method` text,
	`tenant_id` text,
	`sid` text NOT NULL,
	`exp` integer NOT NULL
);

CREATE INDEX `oidc_codes_exp` ON `oidc_codes` (`exp`);
CREATE TABLE `oidc_consents` (
	`identity_id` text NOT NULL,
	`client_id` text NOT NULL,
	`scope` text NOT NULL,
	`granted_at` integer NOT NULL
);

CREATE UNIQUE INDEX `oidc_consents_id_client` ON `oidc_consents` (`identity_id`,`client_id`);
CREATE TABLE `oidc_refresh_tokens` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`family_id` text NOT NULL,
	`client_id` text NOT NULL,
	`identity_id` text NOT NULL,
	`scope` text NOT NULL,
	`tenant_id` text,
	`exp` integer NOT NULL,
	`consumed_at` integer
);

CREATE INDEX `oidc_rt_family` ON `oidc_refresh_tokens` (`family_id`);
CREATE INDEX `oidc_rt_exp` ON `oidc_refresh_tokens` (`exp`);