/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { AuthErrorObject } from '../errors'
import type { DataAtRest } from '../types/dataAtRest'

/**
 * AES-256-GCM reference implementation. App supplies a 32-byte master
 * key; this adapter derives a per-record DEK by HKDF-like construction:
 * `(masterKey || identityId || field)` -> sha256 -> 32-byte DEK. The
 * IV is 12 bytes random per encrypt, prepended to the ciphertext.
 *
 * Production deployments should swap in a KMS-backed adapter (AWS KMS,
 * GCP KMS, HashiCorp Vault) that uses envelope encryption. This impl
 * is the contract reference + a workable default for low-volume apps.
 *
 * Output format: `aes-256-gcm$<kid>$<iv-base64>$<tag-base64>$<ct-base64>`
 * self-describing so future key rotations land cleanly.
 */
export interface AesGcmConfig {
  /** Stable key id; written into every ciphertext. Used for rotation. */
  kid: string
  /** 32-byte symmetric master key (UTF-8 string OK if you cast to Buffer). */
  masterKey: Buffer | string
}

export class AesGcmDataAtRest implements DataAtRest.IAdapter {
  readonly id = 'aes-256-gcm'
  private readonly _key: Buffer
  private readonly _kid: string

  constructor(cfg: AesGcmConfig) {
    const key = typeof cfg.masterKey === 'string' ? Buffer.from(cfg.masterKey, 'utf8') : cfg.masterKey
    if (key.length < 32) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `AesGcmDataAtRest: masterKey must be >= 32 bytes (was ${key.length})`,
      })
    }
    this._key = key.subarray(0, 32)
    this._kid = cfg.kid
  }

  private _derive(ctx: DataAtRest.IContext): Buffer {
    // Per-record DEK = sha256(masterKey || identityId || field).
    // Light-weight HKDF substitute - KMS adapters do real envelope encryption.
    const { createHash } = require('node:crypto') as typeof import('node:crypto')
    return createHash('sha256').update(this._key).update(ctx.identityId).update(ctx.field).digest()
  }

  async encrypt(plain: string, ctx: DataAtRest.IContext): Promise<string> {
    const dek = this._derive(ctx)
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', dek, iv)
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return `aes-256-gcm$${this._kid}$${iv.toString('base64url')}$${tag.toString('base64url')}$${ct.toString('base64url')}`
  }

  async decrypt(cipherText: string, ctx: DataAtRest.IContext): Promise<string> {
    const parts = cipherText.split('$')
    if (parts.length !== 5 || parts[0] !== 'aes-256-gcm') {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: malformed ciphertext' })
    }
    const [, _kid, ivB64, tagB64, ctB64] = parts as [string, string, string, string, string]
    const dek = this._derive(ctx)
    const iv = Buffer.from(ivB64, 'base64url')
    const tag = Buffer.from(tagB64, 'base64url')
    const ct = Buffer.from(ctB64, 'base64url')
    const decipher = createDecipheriv('aes-256-gcm', dek, iv)
    decipher.setAuthTag(tag)
    const plain = Buffer.concat([decipher.update(ct), decipher.final()])
    return plain.toString('utf8')
  }

  needsReEncrypt(cipherText: string): boolean {
    const parts = cipherText.split('$')
    if (parts.length < 2) return true
    return parts[1] !== this._kid
  }
}
