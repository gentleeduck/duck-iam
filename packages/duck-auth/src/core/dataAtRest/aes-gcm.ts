import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { AuthErrorObject } from '../errors'
import type { AuthDataAtRest } from '../types/dataAtRest'

export class AesGcmDataAtRest implements AuthDataAtRest.IAdapter {
  readonly id = 'aes-256-gcm'
  private readonly _currentKid: string
  /** Map of kid -> 32-byte master key. Includes the current key + every
   * `previousKeys` entry. Decrypt looks up by ciphertext's kid; encrypt
   * always uses `_currentKid`. */
  private readonly _keys: Map<string, Buffer>

  constructor(cfg: AesGcmDataAtRest.IConfig) {
    this._currentKid = cfg.kid
    this._keys = new Map()
    this._keys.set(cfg.kid, normalizeKey(cfg.masterKey))
    // Previous-keys ring keyed by kid; rotation must not strand existing ciphertexts.
    for (const k of cfg.previousKeys ?? []) {
      if (this._keys.has(k.kid)) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: `AesGcmDataAtRest: duplicate kid '${k.kid}' across current + previousKeys`,
        })
      }
      this._keys.set(k.kid, normalizeKey(k.masterKey))
    }
  }

  private _derive(masterKey: Buffer, ctx: AuthDataAtRest.IContext): Buffer {
    // DEK = sha256(masterKey || identityId || field); deterministic, so
    // each encrypt samples a fresh 12-byte IV (GCM birthday bound ~2^48).
    return createHash('sha256').update(masterKey).update(ctx.identityId).update(ctx.field).digest()
  }

  async encrypt(plain: string, ctx: AuthDataAtRest.IContext): Promise<string> {
    const masterKey = this._keys.get(this._currentKid)
    if (!masterKey) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: current key missing from ring' })
    }
    // Cap plaintext at 1 MiB so a hostile caller cannot drive multi-GB
    // encrypt cycles + base64 expansion via this surface. Real PII fields
    // are tens to hundreds of bytes; 1 MiB is generous.
    if (typeof plain !== 'string' || plain.length > 1_048_576) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: plaintext must be a <=1MiB string' })
    }
    const dek = this._derive(masterKey, ctx)
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', dek, iv)
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return `aes-256-gcm$${this._currentKid}$${iv.toString('base64url')}$${tag.toString('base64url')}$${ct.toString('base64url')}`
  }

  async decrypt(cipherText: string, ctx: AuthDataAtRest.IContext): Promise<string> {
    if (typeof cipherText !== 'string' || cipherText.length === 0 || cipherText.length > 1_048_576) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: ciphertext must be a 1B-1MiB string' })
    }
    const parts = cipherText.split('$')
    if (parts.length !== 5 || parts[0] !== 'aes-256-gcm') {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: malformed ciphertext' })
    }
    // Destructure WITHOUT an `as` cast - the length+kind check above
    // guarantees parts has 5 strings; downstream guards reject any
    // empty / malformed component.
    const kid = parts[1]
    const ivB64 = parts[2]
    const tagB64 = parts[3]
    const ctB64 = parts[4]
    if (kid === undefined || ivB64 === undefined || tagB64 === undefined || ctB64 === undefined) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: malformed ciphertext' })
    }
    // select the master key by the ciphertext's kid, NOT the
    // current kid. Previously the kid was parsed but discarded - new
    // deployments could not decrypt anything written before rotation.
    const masterKey = this._keys.get(kid)
    if (!masterKey) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `aes-256-gcm: ciphertext kid '${kid}' not in key ring (rotation?). Add to previousKeys to recover.`,
      })
    }
    const dek = this._derive(masterKey, ctx)
    const iv = Buffer.from(ivB64, 'base64url')
    const tag = Buffer.from(tagB64, 'base64url')
    const ct = Buffer.from(ctB64, 'base64url')
    // Require 12-byte IV and 16-byte tag (standard GCM); shorter values
    // weaken the cipher even though Node accepts them.
    if (iv.length !== 12) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: IV must be 12 bytes' })
    }
    if (tag.length !== 16) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: auth tag must be 16 bytes' })
    }
    const decipher = createDecipheriv('aes-256-gcm', dek, iv)
    decipher.setAuthTag(tag)
    // Wrap final() so an auth-tag mismatch surfaces as AUTH/MISCONFIGURED
    // instead of leaking Node's ERR_OSSL_* internals.
    let plain: Buffer
    try {
      plain = Buffer.concat([decipher.update(ct), decipher.final()])
    } catch {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'aes-256-gcm: auth-tag mismatch' })
    }
    return plain.toString('utf8')
  }

  needsReEncrypt(cipherText: string): boolean {
    const parts = cipherText.split('$')
    if (parts.length < 2) return true
    return parts[1] !== this._currentKid
  }
}

/** Validate + normalize a master key. Throws on too-short. */
function normalizeKey(masterKey: Buffer | string): Buffer {
  const key = typeof masterKey === 'string' ? Buffer.from(masterKey, 'utf8') : masterKey
  if (key.length < 32) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: `AesGcmDataAtRest: masterKey must be >= 32 bytes (was ${key.length})`,
    })
  }
  return key.subarray(0, 32)
}

export namespace AesGcmDataAtRest {
  export interface IConfig {
    /** Stable key id; written into every ciphertext. Used for rotation. */
    kid: string
    /** 32-byte symmetric master key (UTF-8 string OK if you cast to Buffer). */
    masterKey: Buffer | string
    /**
     * Old keys retained for decrypting pre-rotation ciphertexts. Each
     * entry's `kid` MUST match the kid embedded in the ciphertexts it
     * can decrypt. Operators add the old (kid, masterKey) here when
     * rotating; remove an entry only after every ciphertext under that
     * kid has been re-encrypted (use `needsReEncrypt` to detect them).
     */
    previousKeys?: Array<{ kid: string; masterKey: Buffer | string }>
  }
}
