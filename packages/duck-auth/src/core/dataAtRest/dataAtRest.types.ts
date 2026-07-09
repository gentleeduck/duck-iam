/** KMS + data-at-rest contracts — envelope-encryption provider and field-level encrypt/decrypt adapter. */

/** Envelope-encryption KMS provider contract: vendor-neutral 2-method shape (`generateDataKey` / `decryptDataKey`). */
export namespace Kms {
  /** Encryption context (AAD) - binds the wrapped DEK to `{identityId, field}` server-side. */
  export type EncryptionContext = Record<string, string>

  export type DataKey = {
    /** 32-byte plaintext DEK. Callers MUST zero it after use. */
    plaintext: Uint8Array
    /** KMS-wrapped DEK. Opaque blob - pass back to `decryptDataKey`. */
    ciphertext: Uint8Array
    /** Key id the wrapped DEK was produced under (helps rotation auditing). */
    keyId: string
  }

  export type Provider = {
    /** Stable adapter id for audit logs / strict() reporting (e.g., 'aws-kms', 'gcp-kms'). */
    readonly id: string
    /**
     * Request a new 256-bit DEK from the KMS. Most providers return
     * (plaintext, wrapped) atomically in a single call to avoid
     * exposing two independent failure modes.
     */
    generateDataKey(ctx?: EncryptionContext): Promise<DataKey>
    /**
     * Unwrap a previously-generated DEK. Must be called with the same
     * encryption context the DEK was generated with, or the KMS will
     * reject the request (AWS/GCP both enforce this strictly).
     */
    decryptDataKey(wrapped: Uint8Array, ctx?: EncryptionContext): Promise<Uint8Array>
  }
}

/** Data-at-rest encryption adapter; field-level encrypt/decrypt with `(field, identityId)` AAD context. */
export namespace DataAtRest {
  export type Context = {
    /** Field name in Identity.profile that's being encrypted. */
    field: string
    /** Identity row id; lets adapters tie keys to subjects + meet
     *  GDPR right-to-erasure by destroying the per-subject DEK.
     */
    identityId: string
    /** Optional opaque tag for tenant or row revision; passes through. */
    tag?: string
  }

  export type Adapter = {
    /** Stable adapter id (audit-log / strict() reporting). */
    readonly id: string
    /** Encrypt plaintext. Returns opaque ciphertext (caller-side base64 if needed). */
    encrypt(plain: string, ctx: Context): Promise<string>
    /** Decrypt opaque ciphertext. Returns plaintext. */
    decrypt(cipher: string, ctx: Context): Promise<string>
    /** Whether the key version of `cipher` is older than the current; rotation trigger. */
    needsReEncrypt(cipher: string): boolean
  }
}
