/** Key management: wrapping and unwrapping a data key under an operator-held master key. */
export namespace Kms {
  /** Encryption context (AAD), binding the wrapped DEK to `{identityId, field}` server-side. */
  export type EncryptionContext = Record<string, string>

  export type DataKey = {
    /** 32-byte plaintext DEK. Callers MUST zero it after use. */
    plaintext: Uint8Array
    /** KMS-wrapped DEK, opaque; pass it back to `decryptDataKey`. */
    ciphertext: Uint8Array
    /** Key id the wrapped DEK was produced under, for rotation auditing. */
    keyId: string
  }

  export type Provider = {
    /** Stable id for audit logs and strict() reporting, such as 'aws-kms' or 'gcp-kms'. */
    readonly id: string
    /** Most providers answer (plaintext, wrapped) in one call, so there is only one failure mode. */
    generateDataKey(ctx?: EncryptionContext): Promise<DataKey>
    /** Must carry the same encryption context the DEK was generated with; AWS and GCP both refuse
     *  the request otherwise. */
    decryptDataKey(wrapped: Uint8Array, ctx?: EncryptionContext): Promise<Uint8Array>
  }
}

/** Field-level encryption: the encrypt/decrypt contract and the context it binds ciphertext to. */
export namespace DataAtRest {
  export type Context = {
    /** Field name in Identity.profile that's being encrypted. */
    field: string
    /** Lets an adapter tie keys to subjects, so GDPR right-to-erasure is met by destroying the
     *  per-subject DEK. */
    identityId: string
    /** Opaque tag for a tenant or row revision; passes straight through. */
    tag?: string
  }

  export type Adapter = {
    /** Stable id for audit logs and strict() reporting. */
    readonly id: string
    /** The ciphertext is opaque; base64 it caller-side if the column needs that. */
    encrypt(plain: string, ctx: Context): Promise<string>
    decrypt(cipher: string, ctx: Context): Promise<string>
    /** Whether `cipher`'s key version is older than the current one, which is the rotation trigger. */
    needsReEncrypt(cipher: string): boolean
  }
}
