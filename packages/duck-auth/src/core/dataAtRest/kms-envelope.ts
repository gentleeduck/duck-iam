import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { AuthError } from '../errors'
import { CIPHERTEXT_MAX_LENGTH, PLAINTEXT_MAX_LENGTH } from './dataAtRest.constants'
import type { DataAtRest, Kms } from './dataAtRest.types'

/**
 * Envelope encryption over any `Kms.Provider`: a per-record DEK and AES-256-GCM locally, with
 * `{identityId, field}` pinned in the KMS encryption context (AAD) so a ciphertext cannot be relocated.
 */
export class AuthKmsEnvelopeDataAtRest implements DataAtRest.Adapter {
  readonly id: string
  private readonly _kms: Kms.Provider

  constructor(cfg: AuthKmsEnvelopeDataAtRest.Cfg) {
    this._kms = cfg.kms
    this.id = `kms-envelope:${cfg.kms.id}`
  }

  /** Mints a per-record data key, encrypts locally under it, and stores it wrapped alongside. */
  async encrypt(plain: string, ctx: DataAtRest.Context): Promise<string> {
    if (typeof plain !== 'string' || plain.length > PLAINTEXT_MAX_LENGTH) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: plaintext must be a <=1MiB string' })
    }
    const dek = await this._kms.generateDataKey(this._aad(ctx))
    if (dek.plaintext.length !== 32) {
      dek.plaintext.fill(0)
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `kms-envelope: KMS returned ${dek.plaintext.length}-byte DEK; expected 32`,
      })
    }
    // SECURITY: an empty wrapped DEK stores a value nothing can ever decrypt.
    if (dek.ciphertext.length === 0) {
      dek.plaintext.fill(0)
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'kms-envelope: KMS returned an empty wrapped DEK' })
    }
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', dek.plaintext, iv)
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    // Zeroed as soon as AES-GCM has consumed it: the wrapped form is what persists, and holding the
    // plaintext longer only widens the memory-disclosure radius.
    dek.plaintext.fill(0)
    return [
      'kms-env',
      'v1',
      encodeURIComponent(dek.keyId),
      Buffer.from(dek.ciphertext).toString('base64url'),
      iv.toString('base64url'),
      tag.toString('base64url'),
      ct.toString('base64url'),
    ].join('$')
  }

  /** Unwraps the record's own data key through KMS, then decrypts locally. */
  async decrypt(cipherText: string, ctx: DataAtRest.Context): Promise<string> {
    if (typeof cipherText !== 'string' || cipherText.length > CIPHERTEXT_MAX_LENGTH) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: ciphertext is not a string or oversize' })
    }
    const [prefix, version, , wrappedB64, ivB64, tagB64, ctB64, ...rest] = cipherText.split('$')
    if (
      prefix !== 'kms-env' ||
      version !== 'v1' ||
      wrappedB64 === undefined ||
      ivB64 === undefined ||
      tagB64 === undefined ||
      ctB64 === undefined ||
      rest.length > 0
    ) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: malformed ciphertext' })
    }
    const wrapped = Buffer.from(wrappedB64, 'base64url')
    const iv = Buffer.from(ivB64, 'base64url')
    const tag = Buffer.from(tagB64, 'base64url')
    const ct = Buffer.from(ctB64, 'base64url')
    // SECURITY: standard GCM sizes, as the aes-gcm adapter checks. Node accepts a shorter tag - it only
    // warns - and a 32-bit tag is a forgery target of 2^32 rather than 2^128, on a column whose whole
    // purpose is to hold when someone can already write to it. Checked before the KMS round trip.
    if (wrapped.length === 0) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: wrapped DEK is empty' })
    }
    if (iv.length !== 12) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: IV must be 12 bytes' })
    }
    if (tag.length !== 16) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: auth tag must be 16 bytes' })
    }
    const dekPlain = await this._kms.decryptDataKey(wrapped, this._aad(ctx))
    if (dekPlain.length !== 32) {
      dekPlain.fill(0)
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `kms-envelope: KMS returned ${dekPlain.length}-byte DEK on decrypt; expected 32`,
      })
    }
    try {
      const decipher = createDecipheriv('aes-256-gcm', dekPlain, iv)
      decipher.setAuthTag(tag)
      const plain = Buffer.concat([decipher.update(ct), decipher.final()])
      return plain.toString('utf8')
    } catch {
      // A forged or corrupt ciphertext reached `final()`. Unwrapped, it leaves as Node's own
      // "Unsupported state or unable to authenticate data", which no error map knows and no caller can match.
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'kms-envelope: auth-tag mismatch' })
    } finally {
      // Always zero the unwrapped DEK, even on failure.
      dekPlain.fill(0)
    }
  }

  /** Always false: KMS rotates server-side under the same key id, and retiring a key is re-encrypted out of band. */
  needsReEncrypt(_cipherText: string): boolean {
    return false
  }

  private _aad(ctx: DataAtRest.Context): Kms.EncryptionContext {
    const aad: Kms.EncryptionContext = {
      field: ctx.field,
      identityId: ctx.identityId,
    }
    if (ctx.tag !== undefined) aad.tag = ctx.tag
    return aad
  }
}

/** Configuration for the envelope encryptor that wraps each data key with a KMS provider. */
export namespace AuthKmsEnvelopeDataAtRest {
  /** The KMS provider that wraps each data key. */
  export interface Cfg {
    /** Mints each data key and unwraps it. */
    kms: Kms.Provider
  }
}

/** Constructs an {@link AuthKmsEnvelopeDataAtRest} encryptor. */
export function authKmsEnvelopeDataAtRest(
  ...args: ConstructorParameters<typeof AuthKmsEnvelopeDataAtRest>
): AuthKmsEnvelopeDataAtRest {
  return new AuthKmsEnvelopeDataAtRest(...args)
}
