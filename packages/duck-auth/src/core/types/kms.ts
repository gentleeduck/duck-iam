/** Envelope-encryption KMS provider contract: vendor-neutral 2-method shape (`generateDataKey` / `decryptDataKey`). */
export namespace AuthKms {
  /** Encryption context (AAD) - binds the wrapped DEK to `{identityId, field}` server-side. */
  export type IEncryptionContext = Record<string, string>

  export interface IDataKey {
    /** 32-byte plaintext DEK. Callers MUST zero it after use. */
    plaintext: Uint8Array
    /** KMS-wrapped DEK. Opaque blob - pass back to `decryptDataKey`. */
    ciphertext: Uint8Array
    /** Key id the wrapped DEK was produced under (helps rotation auditing). */
    keyId: string
  }

  export interface IProvider {
    /** Stable adapter id for audit logs / strict() reporting (e.g., 'aws-kms', 'gcp-kms'). */
    readonly id: string
    /**
     * Request a new 256-bit DEK from the KMS. Most providers return
     * (plaintext, wrapped) atomically in a single call to avoid
     * exposing two independent failure modes.
     */
    generateDataKey(ctx?: IEncryptionContext): Promise<IDataKey>
    /**
     * Unwrap a previously-generated DEK. Must be called with the same
     * encryption context the DEK was generated with, or the KMS will
     * reject the request (AWS/GCP both enforce this strictly).
     */
    decryptDataKey(wrapped: Uint8Array, ctx?: IEncryptionContext): Promise<Uint8Array>
  }
}
