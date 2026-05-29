import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { AuthErrorObject } from '../errors'
import type { DataAtRest } from '../types/dataAtRest'
import type { Kms } from '../types/kms'

/**
 * Envelope-encryption `DataAtRest.IAdapter` driven by any
 * `Kms.IProvider`. Each call to `encrypt` requests a fresh DEK from
 * the KMS, encrypts the plaintext locally with AES-256-GCM, and
 * stores both the wrapped DEK and the ciphertext together. `decrypt`
 * unwraps the DEK via the KMS and runs the AES-GCM inverse locally.
 *
 * This is the production path documented in DESIGN §1 ("KMS adapters
 * via contract"). For dev / low-throughput / no-KMS deployments,
 * `AesGcmDataAtRest` remains the reference implementation.
 *
 * Ciphertext layout (versioned with `kms-env$v1`):
 *
 *     kms-env$v1$<keyId>$<wrappedB64u>$<ivB64u>$<tagB64u>$<ctB64u>
 *
 * The `keyId` is whatever the provider returns from `generateDataKey`
 * and is informational only - `decryptDataKey` is what actually
 * resolves the DEK (and many KMSes can do that across rotations).
 *
 * The encryption context passed to the KMS includes
 * `{identityId, field}` so the KMS itself enforces that a wrapped
 * DEK can only be unwrapped for the same record it was generated
 * for. This is the *AAD pin* that protects against ciphertext
 * relocation attacks across rows.
 */
export class KmsEnvelopeDataAtRest implements DataAtRest.IAdapter {
  readonly id: string
  private readonly _kms: Kms.IProvider

  constructor(cfg: KmsEnvelopeDataAtRest.IConfig) {
    this._kms = cfg.kms
    this.id = `kms-envelope:${cfg.kms.id}`
  }

  async encrypt(plain: string, ctx: DataAtRest.IContext): Promise<string> {
    const dek = await this._kms.generateDataKey(this._aad(ctx))
    if (dek.plaintext.length !== 32) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `kms-envelope: KMS returned ${dek.plaintext.length}-byte DEK; expected 32`,
      })
    }
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', dek.plaintext, iv)
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    // zero the plaintext DEK as soon as AES-GCM has consumed it.
    // The wrapped form is what we persist; holding the plaintext any
    // longer just widens the memory-disclosure blast radius.
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

  async decrypt(cipherText: string, ctx: DataAtRest.IContext): Promise<string> {
    const parts = cipherText.split('$')
    if (parts.length !== 7 || parts[0] !== 'kms-env' || parts[1] !== 'v1') {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'kms-envelope: malformed ciphertext' })
    }
    const [, , , wrappedB64, ivB64, tagB64, ctB64] = parts as [string, string, string, string, string, string, string]
    const wrapped = Buffer.from(wrappedB64, 'base64url')
    const dekPlain = await this._kms.decryptDataKey(wrapped, this._aad(ctx))
    if (dekPlain.length !== 32) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `kms-envelope: KMS returned ${dekPlain.length}-byte DEK on decrypt; expected 32`,
      })
    }
    const iv = Buffer.from(ivB64, 'base64url')
    const tag = Buffer.from(tagB64, 'base64url')
    const ct = Buffer.from(ctB64, 'base64url')
    try {
      const decipher = createDecipheriv('aes-256-gcm', dekPlain, iv)
      decipher.setAuthTag(tag)
      const plain = Buffer.concat([decipher.update(ct), decipher.final()])
      return plain.toString('utf8')
    } finally {
      // Always zero the unwrapped DEK, even on failure.
      dekPlain.fill(0)
    }
  }

  needsReEncrypt(_cipherText: string): boolean {
    // KMS handles key rotation server-side under the same keyId, so
    // ciphertexts don't carry a rotation-version we can compare to.
    // Operators trigger re-encrypt out-of-band when they retire a key.
    return false
  }

  private _aad(ctx: DataAtRest.IContext): Kms.IEncryptionContext {
    const aad: Kms.IEncryptionContext = {
      field: ctx.field,
      identityId: ctx.identityId,
    }
    if (ctx.tag !== undefined) aad.tag = ctx.tag
    return aad
  }
}

/**
 * Namespace merge for KmsEnvelopeDataAtRest.
 */
export namespace KmsEnvelopeDataAtRest {
  export interface IConfig {
    kms: Kms.IProvider
  }
}
