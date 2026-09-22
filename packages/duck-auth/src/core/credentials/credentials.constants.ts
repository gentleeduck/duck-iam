import type { Credential } from './credentials.types'

/** Every credential kind a row may carry. Purpose, not kind, distinguishes the recovery rows. */
export const AUTH_CREDENTIAL_KINDS = [
  'password',
  'passkey',
  'webauthn-mfa',
  'oauth',
  'magic-link',
  'totp',
  'recovery',
  'api-key',
] as const

/** Read and delete recovery rows by purpose, never by kind alone: every one of these shares `recovery`. */
export const RECOVERY_PURPOSES = {
  accountDeletion: 'account-deletion',
  accountDeletionCancel: 'account-deletion-cancel',
  emailVerification: 'email-verification',
  mfaBackupCode: 'mfa-backup-code',
  passwordReset: 'password-reset',
  signupFlow: 'signup-flow',
  trustedDevice: 'trusted-device',
} as const

/** An allowlist: anything absent is dropped, so a key that turns out to hold a secret cannot leak by
 *  being forgotten. The cost is that operator-written keys do not export. */
export const PUBLIC_METADATA_KEYS: Record<Credential.Kind, readonly string[]> = {
  'api-key': ['name', 'scopes'],
  'magic-link': ['email', 'channel'],
  oauth: ['provider', 'sub', 'familyId', 'generation', 'revokedAt'],
  passkey: ['publicKey', 'counter', 'transports', 'aaguid', 'deviceType', 'backedUp'],
  password: ['algorithm'],
  recovery: ['purpose', 'reason', 'flow', 'issuedAt'],
  totp: ['confirmed', 'lastTotpStep'],
  'webauthn-mfa': ['publicKey', 'counter', 'transports'],
}
