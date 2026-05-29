/**
 * Envelope-encryption KMS provider contract. Abstracts AWS KMS / GCP
 * KMS / Azure Key Vault / Vault Transit behind a 2-method interface so
 * the library never imports a vendor SDK directly. Combined with
 * `KmsEnvelopeDataAtRest` (under `src/core/dataAtRest/kms-envelope.ts`),
 * this lets operators wire a real KMS into `DataAtRest.IAdapter`
 * without rewriting the encrypt/decrypt path.
 *
 * The two methods follow the AWS KMS shape because every other vendor
 * surfaces the same primitives:
 *   - `generateDataKey`  -> plaintext DEK + KMS-wrapped DEK
 *   - `decryptDataKey`   -> plaintext DEK from the wrapped form
 *
 * GCP KMS calls the wrapped form a "wrapped DEK"; AWS calls it a
 * "ciphertext blob"; Vault Transit returns an "encrypted_key". They
 * all behave identically here.
 */
export namespace Kms {
  /**
   * Optional encryption context, passed through to the KMS. AWS KMS
   * and GCP KMS both validate the context on decrypt - supplying it
   * here binds the wrapped DEK to a specific (identityId, field)
   * subject and prevents ciphertext copy-paste attacks across rows.
   */
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
