/** Data-at-rest encryption adapter; field-level encrypt/decrypt with `(field, identityId)` AAD context. */
export namespace AuthDataAtRest {
  export interface IContext {
    /** Field name in AuthIdentity.profile that's being encrypted. */
    field: string
    /** AuthIdentity row id; lets adapters tie keys to subjects + meet
     *  GDPR right-to-erasure by destroying the per-subject DEK.
     */
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
