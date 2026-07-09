/** Infrastructure contracts — tenant context, hasher, KMS, data-at-rest, limiter, idempotency, channel. */
import type { Identity } from '~/core/identities/identities.types'

/**
 * Per-request tenant scope. Framework adapters inject this via AsyncLocalStorage;
 * stores receive it on every call. Apps without multi-tenancy leave tenantId undefined.
 */
export interface TenantContext {
  tenantId?: string
}

/** Password hasher contract. Must be salt-deterministic, constant-time verify, and expose `needsRehash`. */
export namespace Hasher {
  export interface IHasher {
    /** Identifier for the algorithm + parameter set encoded into the hash. */
    readonly id: string
    hash(plaintext: string): Promise<string>
    verify(plaintext: string, encoded: string): Promise<boolean>
    /** True when `encoded` was produced by an older/weaker parameter set than current. */
    needsRehash(encoded: string): boolean
  }
}

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

/**
 * Rate-limit + lockout adapter. Brute-force protection is non-optional; strict()
 * refuses production boot without one wired. Dimensions configurable per app
 * (identity, ip, composite). Reference impls: memory (token bucket), redis (Lua).
 */
export namespace Limiter {
  export type Result = {
    ok: boolean
    remaining: number
    resetAt: Date
  }

  export type Limiter = {
    consume(key: string, weight?: number): Promise<Result>
    reset(key: string): Promise<void>
  }
}

/** Outbound message channel (email / SMS / web-push). Library pre-signs URLs; templates get safe vars only. */
export namespace Channel {
  export type Kind = 'email' | 'sms' | 'webpush'

  export type SendInput<
    Vars = Record<string, unknown>,
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  > = {
    /** Resolved recipient - the channel decides which `identity.profile` field to use. */
    identity: Identity.Me<Profile>
    /** Library-chosen template id; channel impl maps to its own template store. */
    templateId: string
    /** Pre-rendered vars (URLs already signed, strings already i18n-resolved). */
    vars: Vars
    tenant: TenantContext
  }

  export type SendResult = {
    ok: boolean
    /** Provider-side id (for support diagnostics). Channels may omit. */
    providerMessageId?: string
    error?: string
  }

  export type Channel<Vars = Record<string, unknown>> = {
    readonly kind: Kind
    readonly id: string
    send(input: SendInput<Vars>): Promise<SendResult>
  }
}
