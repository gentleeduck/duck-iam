import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import type { DataAtRest, Kms } from '../dataAtRest/dataAtRest.types'
import { AuthError } from '../errors'

/**
 * Envelope-encryption `DataAtRest.IAdapter` driven by any `Kms.IProvider`.
 * Per-record DEK + AES-256-GCM locally; `{identityId, field}` is pinned in
 * the KMS encryption context (AAD) to defeat ciphertext relocation.
 *
 * Ciphertext layout: `kms-env$v1$<keyId>$<wrappedB64u>$<ivB64u>$<tagB64u>$<ctB64u>`.
 */
export class AuthKmsEnvelopeDataAtRest implements DataAtRest.Adapter {
  readonly id: string
  private readonly _kms: Kms.Provider

  constructor(cfg: AuthKmsEnvelopeDataAtRest.Cfg) {
    this._kms = cfg.kms
    this.id = `kms-envelope:${cfg.kms.id}`
  }

  async encrypt(plain: string, ctx: DataAtRest.Context): Promise<string> {
    const dek = await this._kms.generateDataKey(this._aad(ctx))
    if (dek.plaintext.length !== 32) {
      throw new AuthError('AUTH_MISCONFIGURED', {
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

  async decrypt(cipherText: string, ctx: DataAtRest.Context): Promise<string> {
    const parts = cipherText.split('$')
    if (parts.length !== 7 || parts[0] !== 'kms-env' || parts[1] !== 'v1') {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'kms-envelope: malformed ciphertext' })
    }
    const [, , , wrappedB64, ivB64, tagB64, ctB64] = parts as [string, string, string, string, string, string, string]
    const wrapped = Buffer.from(wrappedB64, 'base64url')
    const dekPlain = await this._kms.decryptDataKey(wrapped, this._aad(ctx))
    if (dekPlain.length !== 32) {
      throw new AuthError('AUTH_MISCONFIGURED', {
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

  private _aad(ctx: DataAtRest.Context): Kms.EncryptionContext {
    const aad: Kms.EncryptionContext = {
      field: ctx.field,
      identityId: ctx.identityId,
    }
    if (ctx.tag !== undefined) aad.tag = ctx.tag
    return aad
  }
}

export namespace AuthKmsEnvelopeDataAtRest {
  export interface Cfg {
    kms: Kms.Provider
  }
}

/** Factory around {@link AuthKmsEnvelopeDataAtRest}, for callers who prefer functions to `new`. */
export function authKmsEnvelopeDataAtRest(
  ...args: ConstructorParameters<typeof AuthKmsEnvelopeDataAtRest>
): AuthKmsEnvelopeDataAtRest {
  return new AuthKmsEnvelopeDataAtRest(...args)
}
