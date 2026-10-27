import { AuthError } from '../errors'
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
  mfaChallenge: 'mfa-challenge',
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

/** The last instant every dialect stores: mysql's DATETIME ends with 9999. */
export const LATEST_STORABLE_MS = Date.UTC(9999, 11, 31, 23, 59, 59, 999)

/**
 * The credential dates every store refuses alike: an unreadable date, and one past {@link LATEST_STORABLE_MS}.
 *
 * SECURITY: sqlite binds the NaN of an unreadable date as NULL, so an API key created with
 * `expiresAt: Date.parse('bad')` was stored with no expiry and verified for ever, where memory read it as
 * expired and pg and mysql refused it.
 */
export function assertCredentialDates(
  write: Pick<Credential.CreateInput, 'expiresAt' | 'lastUsedAt' | 'revokedAt'>,
): void {
  for (const key of ['expiresAt', 'lastUsedAt', 'revokedAt'] as const) {
    const value = write[key]
    if (value == null) continue
    const ms = value instanceof Date ? value.getTime() : Number.NaN
    if (!Number.isFinite(ms) || ms > LATEST_STORABLE_MS) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: `${key} is not a date a store can hold` })
    }
  }
}
