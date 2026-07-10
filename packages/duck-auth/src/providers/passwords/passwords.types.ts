import type { Compliance } from '~/core/compliance'
import type { Hasher } from './hashers/hashers.types'
// import type { PasswordsFacet } from './password.facet'

/**
 * Every type the password provider exposes lives under this one namespace, so
 * consumers reach for `Password.Cfg`, `Password.Options`, etc. from a single
 * place.
 */
export namespace Passwords {
  /** Resolved, total facet config — every field explicit (null-discipline). */
  export type Cfg = {
    /** Minimum password length. Default 8; compliance presets force >=12. */
    minLength: number
    /** Maximum password length. Default 1024. SEC: caps argon2/scrypt DoS surface. */
    maxLength: number
    /** Reject obvious junk. Default true. */
    rejectCommon: boolean
    /** Pluggable hasher. Defaults to scrypt (Node built-in, zero deps). */
    hasher: Hasher.Me
    /** Compliance preset(s); ratchets `minLength` up to the preset floor. */
    compliance: Compliance.Preset | Compliance.Preset[]
    /** Per-email rate-limit key prefix. Default 'signin:password:'. */
    limiterKeyPrefix: string
    /** Auto-rehash on successful verify when needsRehash=true. Default true. */
    autoRehash: boolean
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
