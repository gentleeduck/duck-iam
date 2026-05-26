/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Data-at-rest encryption adapter. Field-level encrypt/decrypt for
 * sensitive Identity.profile fields (SSN, DOB, phone) without forcing
 * every consumer onto the same KMS. Library calls encrypt/decrypt with
 * a (field, identityId) context so adapters can derive per-record keys
 * via envelope encryption against AWS KMS / GCP KMS / Vault / etc.
 *
 * DESIGN section C5.
 */
export namespace DataAtRest {
  export interface IContext {
    /** Field name in Identity.profile that's being encrypted. */
    field: string
    /** Identity row id; lets adapters tie keys to subjects + meet
     *  GDPR right-to-erasure by destroying the per-subject DEK. */
    identityId: string
    /** Optional opaque tag for tenant or row revision; passes through. */
    tag?: string
  }

  export interface IAdapter {
    /** Stable adapter id (audit-log / strict() reporting). */
    readonly id: string
    /** Encrypt plaintext. Returns opaque ciphertext (caller-side base64 if needed). */
    encrypt(plain: string, ctx: IContext): Promise<string>
    /** Decrypt opaque ciphertext. Returns plaintext. */
    decrypt(cipher: string, ctx: IContext): Promise<string>
    /** Whether the key version of `cipher` is older than the current; rotation trigger. */
    needsReEncrypt(cipher: string): boolean
  }
}
