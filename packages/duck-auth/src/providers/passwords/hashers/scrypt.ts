import { scrypt as nodeScrypt, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'
import { AuthError } from '~/core/errors'
import type { Hasher } from './hashers.types'

export namespace ScryptHasher {
  export type Params = {
    /** CPU and memory cost, and it must be a power of two. Default 2^17, 131072. */
    N: number
    /** Default 8. */
    r: number
    /** Default 1. */
    p: number
    /** In bytes. Default 64. */
    keylen: number
    /** In bytes. Default 16. */
    saltLen: number
  }
}

const scryptAsync = promisify(nodeScrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem?: number },
) => Promise<Buffer>

/** The ceiling `hash` and `verify` both pass to Node. scrypt needs about `128 * N * r` bytes, so this is
 *  what bounds the two together; 256 MB keeps headroom over the default N of 2^17 at r 8. */
const SCRYPT_MAXMEM = 256 * 1024 * 1024

/** Default parameters tuned for ~150 ms on a 2022-class server CPU. */
export const SCRYPT_DEFAULTS: ScryptHasher.Params = {
  N: 1 << 17,
  r: 8,
  p: 1,
  keylen: 64,
  saltLen: 16,
}

/** `scrypt$<N>$<r>$<p>$<saltBase64>$<keyBase64>`, every field URL-safe base64. Self-describing, so
 *  {@link ScryptHasher.needsRehash} detects parameter drift with no external migration table. */
function encode(N: number, r: number, p: number, salt: Buffer, key: Buffer): string {
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${key.toString('base64url')}`
}

function parse(encoded: string): { N: number; r: number; p: number; salt: Buffer; key: Buffer } | null {
  const parts = encoded.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null
  const [_, Nstr, rStr, pStr, saltB64, keyB64] = parts
  const N = Number(Nstr)
  const r = Number(rStr)
  const p = Number(pStr)
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return null
  if (N < 2 || (N & (N - 1)) !== 0) return null // must be power of two
  const salt = Buffer.from(saltB64 ?? '', 'base64url')
  const key = Buffer.from(keyB64 ?? '', 'base64url')
  // SECURITY: an empty key is not a short key, it is no key, and it is refused here rather than compared.
  // `verify` derives its candidate at the stored key's length, `scrypt` answers an empty buffer for a
  // keylen of 0 instead of throwing, and `timingSafeEqual` calls two empty buffers equal - so a row whose
  // key field had been truncated away verified every password offered to it.
  if (salt.length === 0 || key.length === 0) return null
  return { N, r, p, salt, key }
}

/** Node's own, and the one hasher that needs no dependency. `DEFAULT_PASSWORDS_CONFIG` selects
 *  Argon2id; this is what the CLI, the examples and the test harness pass explicitly. */
export class ScryptHasher implements Hasher.Me {
  readonly id = 'scrypt'
  /** Never, whatever the parameters: the `fipsValidatedHasher` check names Argon2id. Published rather
   *  than left off so the answer is "no" and not "no opinion". */
  readonly __fipsParams = false
  /** Below the floor `SCRYPT_DEFAULTS` sets. Refused by `AuthEngine.strict()` in production only, since a
   *  cheap KDF is what a test suite wants and what a production deployment cannot have. */
  readonly __weakHasherParams: boolean
  private readonly _params: ScryptHasher.Params

  constructor(params: Partial<ScryptHasher.Params> = {}) {
    this._params = { ...SCRYPT_DEFAULTS, ...params }
    // SECURITY: `parse` refuses an empty salt or key because such a row verified every password offered
    // to it - and `hash` was the thing writing them. Measured: `keylen: 0` and `saltLen: 0` each encoded a
    // row with that field blank, so `verify` answered `false` to the correct password for ever after, and
    // nothing said so at any point. `r` and `p` of 0 were accepted by Node and by `parse`, and an `N` that
    // is not a power of two or is NaN threw a raw Node error on the first sign-up rather than here.
    if (!Number.isInteger(this._params.N) || this._params.N < 2 || (this._params.N & (this._params.N - 1)) !== 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `scrypt: N must be a power of two of at least 2, got ${String(this._params.N)}`,
      })
    }
    if (
      !Number.isInteger(this._params.r) ||
      this._params.r < 1 ||
      !Number.isInteger(this._params.p) ||
      this._params.p < 1
    ) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `scrypt: r and p must be whole numbers of at least 1, got r=${String(this._params.r)} p=${String(this._params.p)}`,
      })
    }
    // Node throws inside `scrypt` when `128 * N * r` passes the `maxmem` both calls hand it, which is the
    // first sign-up rather than the boot that wrote the number.
    if (128 * this._params.N * this._params.r > SCRYPT_MAXMEM) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `scrypt: N * r needs ${128 * this._params.N * this._params.r} bytes, over the ${SCRYPT_MAXMEM} maxmem both calls pass`,
      })
    }
    if (!Number.isInteger(this._params.keylen) || this._params.keylen < 16) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `scrypt: keylen must be a whole number of at least 16 bytes, got ${String(this._params.keylen)}`,
      })
    }
    if (!Number.isInteger(this._params.saltLen) || this._params.saltLen < 8) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `scrypt: saltLen must be a whole number of at least 8 bytes, got ${String(this._params.saltLen)}`,
      })
    }
    this.__weakHasherParams =
      this._params.N < 2 ** 14 || this._params.r < 8 || this._params.p < 1 || this._params.keylen < 32
  }

  /** Hashes under a fresh salt, encoding the parameters into the result. */
  async hash(plaintext: string): Promise<string> {
    const salt = randomBytes(this._params.saltLen)
    const key = await scryptAsync(plaintext, salt, this._params.keylen, {
      N: this._params.N,
      r: this._params.r,
      p: this._params.p,
      maxmem: SCRYPT_MAXMEM,
    })
    return encode(this._params.N, this._params.r, this._params.p, salt, key)
  }

  /** Constant-time compare; an unparseable or foreign-format hash is false, not an error. */
  async verify(plaintext: string, encoded: string): Promise<boolean> {
    const parsed = parse(encoded)
    if (!parsed) return false
    try {
      const candidate = await scryptAsync(plaintext, parsed.salt, parsed.key.length, {
        N: parsed.N,
        r: parsed.r,
        p: parsed.p,
        maxmem: SCRYPT_MAXMEM,
      })
      if (candidate.length !== parsed.key.length) return false
      return timingSafeEqual(candidate, parsed.key)
    } catch {
      return false
    }
  }

  /** True when the encoded parameters are weaker than the configured ones, or unreadable. */
  needsRehash(encoded: string): boolean {
    const parsed = parse(encoded)
    if (!parsed) return true
    return (
      parsed.N < this._params.N ||
      parsed.r < this._params.r ||
      parsed.p < this._params.p ||
      parsed.key.length < this._params.keylen
    )
  }
}

/** Constructs a {@link ScryptHasher}. */
export function scryptHasher(...args: ConstructorParameters<typeof ScryptHasher>): ScryptHasher {
  return new ScryptHasher(...args)
}
