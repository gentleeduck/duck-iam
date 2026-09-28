import type { Compliance } from '~/core/compliance'
import type { Hasher } from './hashers/hashers.types'

/** Password provider configuration and the hasher contract it drives. */
export namespace Passwords {
  /** Total: every field explicit. */
  export type Cfg = {
    /** Default 8; the hipaa preset raises it to 12 and fips to 14. */
    minLength: number
    /** Default 1024.
     *  SECURITY: caps the argon2 and scrypt DoS surface. */
    maxLength: number
    /** Rejects obvious junk. Default true. */
    rejectCommon: boolean
    /** Defaults to Argon2id at OWASP parameters, which needs the `@node-rs/argon2` peerDep. */
    hasher: Hasher.Me
    /** Ratchets `minLength` up to the preset's floor. */
    compliance: Compliance.Preset | Compliance.Preset[]
    /** Default 'signin:password:'. */
    limiterKeyPrefix: string
    /** Re-hashes on a successful verify that reported `needsRehash`. Default true. */
    autoRehash: boolean
  }

  /** Unused by password sign-in, kept for parity with the other providers. */
  export type BeginInput = {
    email: string
  }

  /** What a password sign-in takes. */
  export type CompleteInput = {
    email: string
    password: string
  }
}
