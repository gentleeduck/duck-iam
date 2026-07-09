import { resolveCompliance } from '~/core/compliance'
import type { Mfa } from './mfa.types'

/** Default MFA facet config; overridden per-provider via `mfaProvider(cfg)`. */
export const DEFAULT_MFA_CONFIG: Mfa.Config = {
  issuer: 'duck-auth',
  backupCodeCount: 10,
  backupCodeLen: 10,
}

/**
 * Fill every {@link Mfa.Config} field from the optional input + defaults.
 * When a `compliance` preset is supplied, `backupCodeCount` is ratcheted up to
 * that preset's floor (provider-level compliance) — the user's own value can
 * raise it further but never drop below the floor.
 */
export function toMfaConfig(cfg?: Mfa.ConfigInput): Mfa.Config {
  const floor = cfg?.compliance ? resolveCompliance(cfg.compliance).mfa.backupCodeCount : 0
  return {
    issuer: cfg?.issuer ?? DEFAULT_MFA_CONFIG.issuer,
    backupCodeCount: Math.max(cfg?.backupCodeCount ?? DEFAULT_MFA_CONFIG.backupCodeCount, floor),
    backupCodeLen: cfg?.backupCodeLen ?? DEFAULT_MFA_CONFIG.backupCodeLen,
  }
}
