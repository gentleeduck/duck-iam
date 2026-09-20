import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto'
import type { DataAtRest } from '../dataAtRest/dataAtRest.types'
import { AuthError } from '../errors'

/** What every new ciphertext is written as. */
const ALG_CURRENT = 'aes-256-gcm.v2'

/** The original format, read but never written. Its DEK is `sha256(masterKey || identityId || field)` with
 *  nothing between the components, so ('ab', 'c') and ('a', 'bc') derive one key. Kept readable so the change is
 *  not a data loss event; `needsReEncrypt` reports every ciphertext still in it. */
const ALG_LEGACY = 'aes-256-gcm'

const DEK_BYTES = 32

/** Real PII fields are tens to hundreds of bytes; this is generous, and it bounds the encrypt cycle. */
const PLAINTEXT_MAX_LENGTH = 1_048_576

/** What encrypting the largest accepted plaintext produces: three UTF-8 bytes per UTF-16 unit, then
 *  base64url's four characters per three bytes, plus the prefix, kid, IV and tag.
 *  WARN: not the plaintext cap, which let a value over ~786,000 characters encrypt and store, then fail
 *  every read of itself as oversize. */
const CIPHERTEXT_MAX_LENGTH = PLAINTEXT_MAX_LENGTH * 4 + 256

/** AES-256-GCM `DataAtRest.Adapter`. Per-field DEK derived from the master key and the context; each encrypt
 *  samples a fresh 12-byte IV. Rotation goes through `previousKeys`, so old ciphertexts stay readable until they
 *  are re-encrypted under the current kid. Layout: `<alg>$<kid>$<ivB64u>$<tagB64u>$<ctB64u>`. */
export class AuthAesGcmDataAtRest implements DataAtRest.Adapter {
  readonly id = 'aes-256-gcm'
  private readonly _currentKid: string
  /** kid -> 32-byte master key, the current one and every `previousKeys` entry. Decrypt looks up the
   *  ciphertext's kid; encrypt always uses `_currentKid`. */
  private readonly _keys: Map<string, Buffer>

  constructor(cfg: AuthAesGcmDataAtRest.Cfg) {
    this._currentKid = assertKid(cfg.kid)
    this._keys = new Map()
    this._keys.set(cfg.kid, normalizeKey(cfg.masterKey))
    // Keyed by kid, so rotation cannot strand an existing ciphertext.
    for (const k of cfg.previousKeys ?? []) {
      assertKid(k.kid)
      if (this._keys.has(k.kid)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `AuthAesGcmDataAtRest: duplicate kid '${k.kid}' across current + previousKeys`,
        })
      }
      this._keys.set(k.kid, normalizeKey(k.masterKey))
    }
  }

  /** Deterministic, so each encrypt samples a fresh 12-byte IV (GCM birthday bound ~2^48). */
  private _derive(masterKey: Buffer, kid: string, ctx: DataAtRest.Context, alg: string): Buffer {
    if (alg === ALG_LEGACY) {
      return createHash('sha256').update(masterKey).update(ctx.identityId).update(ctx.field).digest()
    }
    return Buffer.from(hkdfSync('sha256', masterKey, Buffer.from(kid, 'utf8'), contextInfo(ctx), DEK_BYTES))
  }

  /** Encrypts under the current key, tagging the ciphertext with its `kid`. */
  async encrypt(plain: string, ctx: DataAtRest.Context): Promise<string> {
    const masterKey = this._keys.get(this._currentKid)
    if (!masterKey) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'aes-256-gcm: current key missing from ring' })
    }
    if (typeof plain !== 'string' || plain.length > PLAINTEXT_MAX_LENGTH) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: plaintext must be a <=1MiB string' })
    }
    const dek = this._derive(masterKey, this._currentKid, ctx, ALG_CURRENT)
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', dek, iv)
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return `${ALG_CURRENT}$${this._currentKid}$${iv.toString('base64url')}$${tag.toString('base64url')}$${ct.toString('base64url')}`
  }

  /** Decrypts under the `kid` the ciphertext names, so a retired key still reads. */
  async decrypt(cipherText: string, ctx: DataAtRest.Context): Promise<string> {
    if (typeof cipherText !== 'string' || cipherText.length === 0 || cipherText.length > CIPHERTEXT_MAX_LENGTH) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: ciphertext is empty or oversize' })
    }
    const parts = cipherText.split('$')
    const alg = parts[0]
    if (parts.length !== 5 || (alg !== ALG_CURRENT && alg !== ALG_LEGACY)) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: malformed ciphertext' })
    }
    // No cast: the length and kind check above leaves five strings, and the guards below reject an
    // empty or malformed component.
    const kid = parts[1]
    const ivB64 = parts[2]
    const tagB64 = parts[3]
    const ctB64 = parts[4]
    if (kid === undefined || ivB64 === undefined || tagB64 === undefined || ctB64 === undefined) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: malformed ciphertext' })
    }
    // By the ciphertext's kid, never the current one, or a rotated deployment cannot read anything
    // written before the rotation.
    const masterKey = this._keys.get(kid)
    if (!masterKey) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `aes-256-gcm: ciphertext kid '${kid}' not in key ring (rotation?). Add to previousKeys to recover.`,
      })
    }
    const dek = this._derive(masterKey, kid, ctx, alg)
    const iv = Buffer.from(ivB64, 'base64url')
    const tag = Buffer.from(tagB64, 'base64url')
    const ct = Buffer.from(ctB64, 'base64url')
    // Standard GCM sizes. Node accepts shorter ones, which weaken the cipher.
    if (iv.length !== 12) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: IV must be 12 bytes' })
    }
    if (tag.length !== 16) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: auth tag must be 16 bytes' })
    }
    const decipher = createDecipheriv('aes-256-gcm', dek, iv)
    decipher.setAuthTag(tag)
    // Wrapped so an auth-tag mismatch surfaces as AUTH_MISCONFIGURED, not Node's ERR_OSSL_* internals.
    let plain: Buffer
    try {
      plain = Buffer.concat([decipher.update(ct), decipher.final()])
    } catch {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'aes-256-gcm: auth-tag mismatch' })
    }
    return plain.toString('utf8')
  }

  /** True once the ciphertext names an algorithm or a `kid` other than the current one. */
  needsReEncrypt(cipherText: string): boolean {
    const parts = cipherText.split('$')
    if (parts.length < 2) return true
    return parts[0] !== ALG_CURRENT || parts[1] !== this._currentKid
  }
}

/** Each component behind its own length, so no two contexts flatten to the same bytes. */
function contextInfo(ctx: DataAtRest.Context): Buffer {
  const out: Buffer[] = []
  for (const component of [ctx.identityId, ctx.field]) {
    const bytes = Buffer.from(String(component), 'utf8')
    const length = Buffer.alloc(4)
    length.writeUInt32BE(bytes.length)
    out.push(length, bytes)
  }
  return Buffer.concat(out)
}

/**
 * Refused at construction, because `$` separates the ciphertext's own fields. A kid carrying one
 * encrypts without complaint and then splits into six parts on the way back, so every read of
 * everything written under it fails as malformed - the write path never says a word. The KMS envelope
 * adapter escapes its key id for the same reason; this one is the operator's own string.
 */
function assertKid(kid: string): string {
  if (typeof kid !== 'string' || kid.length === 0 || kid.includes('$')) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `AuthAesGcmDataAtRest: kid must be a non-empty string without '$' (was '${kid}')`,
    })
  }
  return kid
}

/** Throws when the key is shorter than 32 bytes. */
function normalizeKey(masterKey: Buffer | string): Buffer {
  const key = typeof masterKey === 'string' ? Buffer.from(masterKey, 'utf8') : masterKey
  if (key.length < 32) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `AuthAesGcmDataAtRest: masterKey must be >= 32 bytes (was ${key.length})`,
    })
  }
  return key.subarray(0, 32)
}

/** Configuration for the AES-GCM field encryptor. */
export namespace AuthAesGcmDataAtRest {
  export interface Cfg {
    /** Stable key id; written into every ciphertext. Used for rotation. */
    kid: string
    /** 32-byte symmetric master key; a UTF-8 string is accepted and encoded here. */
    masterKey: Buffer | string
    /** Each entry's `kid` must match the one embedded in the ciphertexts it decrypts. Remove an entry
     *  only once every ciphertext under that kid is re-encrypted, which `needsReEncrypt` reports. */
    previousKeys?: Array<{ kid: string; masterKey: Buffer | string }>
  }
}

/** Constructs an {@link AuthAesGcmDataAtRest} encryptor. */
export function authAesGcmDataAtRest(
  ...args: ConstructorParameters<typeof AuthAesGcmDataAtRest>
): AuthAesGcmDataAtRest {
  return new AuthAesGcmDataAtRest(...args)
}
