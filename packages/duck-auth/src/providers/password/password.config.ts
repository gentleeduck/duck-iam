import { resolveCompliance } from '~/core/compliance'
import { DEFAULT_PASSWORDS_CONFIG } from './password.constants'
import type { Password } from './password.types'

/**
 * Fill every {@link Password.Config} field from the optional input + defaults.
 * When a `compliance` preset is supplied, `minLength` is ratcheted up to that
 * preset's floor (provider-level compliance) — the user's own value can raise
 * it further but never drop below the floor.
 */
export function toPasswordsConfig(cfg?: Password.ConfigInput): Password.Config {
  const floor = cfg?.compliance ? resolveCompliance(cfg.compliance).passwords.minLength : 0
  return {
    minLength: Math.max(cfg?.minLength ?? DEFAULT_PASSWORDS_CONFIG.minLength, floor),
    maxLength: cfg?.maxLength ?? DEFAULT_PASSWORDS_CONFIG.maxLength,
    rejectCommon: cfg?.rejectCommon ?? DEFAULT_PASSWORDS_CONFIG.rejectCommon,
  }
}
