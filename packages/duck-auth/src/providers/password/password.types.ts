import type { Compliance } from '~/core/compliance'
import type { Hasher } from '~/core/types/infra'
import type { PasswordsFacet } from './password.facet'

/**
 * Every type the password provider exposes lives under this one namespace, so
 * consumers reach for `Password.Config`, `Password.Options`, etc. from a single
 * place.
 */
export namespace Password {
  /** Resolved, total facet config — every field explicit (null-discipline). */
  export interface Config {
    /** Minimum password length. Default 8; compliance presets force >=12. */
    minLength: number
    /** Maximum password length. Default 1024. SEC: caps argon2/scrypt DoS surface. */
    maxLength: number
    /** Reject obvious junk. Default true. */
    rejectCommon: boolean
  }

  /**
   * Ergonomic, end-user-facing config. Every field optional; the boundary
   * coalesces each key to its default (`toPasswordsConfig`) so the facet never
   * sees `undefined`.
   */
  export type ConfigInput = {
    minLength?: number
    maxLength?: number
    rejectCommon?: boolean
    /** Pluggable hasher. Defaults to scrypt (Node built-in, zero deps). */
    hasher?: Hasher.IHasher
    /** Compliance preset(s); ratchets `minLength` up to the preset floor. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }

  /** Options for the email+password sign-in provider {@link password}. */
  export type Options = {
    /** Function to find an identity given an email. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /** Bound PasswordsFacet - verify + needsRehash + slow rehash. */
    passwords: PasswordsFacet
    /** Per-email rate-limit key prefix. Default 'signin:password:'. */
    limiterKeyPrefix?: string
    /** Auto-rehash on successful verify when needsRehash=true. Default true. */
    autoRehash?: boolean
  }

  /** Input to `begin` (unused for password sign-in but kept for parity). */
  export type BeginInput = {
    email: string
  }

  /** Input to `complete`. */
  export type CompleteInput = {
    email: string
    password: string
  }
}
