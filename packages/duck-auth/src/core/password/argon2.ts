/** Argon2id-backed password hasher (compliance presets); needs `@node-rs/argon2` peerDep. */

import { AuthErrorObject } from '../errors'
import type { AuthHasher } from '../types/hasher'

/** Conservative OWASP defaults. */
export const ARGON2ID_DEFAULTS: AuthArgon2idHasher.IParams = {
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
}

/** Tuned for compliance preset (HIPAA / SOC2 / FIPS). */
export const ARGON2ID_COMPLIANCE: AuthArgon2idHasher.IParams = {
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
  saltLength: 16,
}

interface NodeRsArgon2Module {
  hash: (
    password: string | Buffer,
    options?: {
      algorithm?: number
      memoryCost?: number
      timeCost?: number
      parallelism?: number
      hashLength?: number
      saltLength?: number
    },
  ) => Promise<string>
  verify: (encoded: string, password: string | Buffer) => Promise<boolean>
  Algorithm?: { Argon2id: number }
}

let _argon2Module: NodeRsArgon2Module | null = null
async function loadArgon2(): Promise<NodeRsArgon2Module> {
  if (_argon2Module) return _argon2Module
  try {
    const mod = (await import('@node-rs/argon2' as string)) as NodeRsArgon2Module
    _argon2Module = mod
    return mod
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'AuthArgon2idHasher requires the @node-rs/argon2 peerDep. ' +
        'Install via `bun add @node-rs/argon2` (or `npm install @node-rs/argon2`).',
    })
  }
}

/** Argon2id hasher; lazy-imports `@node-rs/argon2` and encodes the PHC string `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`. */
export class AuthArgon2idHasher implements AuthHasher.IHasher {
  readonly id = 'argon2id'
  private readonly _params: AuthArgon2idHasher.IParams

  constructor(params: Partial<AuthArgon2idHasher.IParams> = {}) {
    this._params = { ...ARGON2ID_DEFAULTS, ...params }
  }

  /** Hash plaintext. Async; lazy-loads @node-rs/argon2 on first call. */
  async hash(plaintext: string): Promise<string> {
    const argon = await loadArgon2()
    return argon.hash(plaintext, {
      algorithm: argon.Algorithm?.Argon2id ?? 2,
      memoryCost: this._params.memoryCost,
      timeCost: this._params.timeCost,
      parallelism: this._params.parallelism,
      hashLength: this._params.hashLength,
      saltLength: this._params.saltLength,
    })
  }

  /** Verify in constant time. Returns false on malformed input rather than throwing. */
  async verify(plaintext: string, encoded: string): Promise<boolean> {
    if (!encoded.startsWith('$argon2id$')) return false
    try {
      const argon = await loadArgon2()
      return argon.verify(encoded, plaintext)
    } catch {
      return false
    }
  }

  /**
   * True when the stored hash was produced with weaker params than the
   * current set. Parses the PHC string's `m=..,t=..,p=..` field and
   * compares each field independently; weaker on ANY dimension triggers.
   */
  needsRehash(encoded: string): boolean {
    if (!encoded.startsWith('$argon2id$')) return true
    const match = encoded.match(/\$m=(\d+),t=(\d+),p=(\d+)\$/)
    if (!match) return true
    const [, mStr, tStr, pStr] = match
    const m = Number(mStr)
    const t = Number(tStr)
    const p = Number(pStr)
    return m < this._params.memoryCost || t < this._params.timeCost || p < this._params.parallelism
  }
}

/** Namespace merge - AuthArgon2idHasher.IParams alongside the class. */
export namespace AuthArgon2idHasher {
  export interface IParams {
    /** Memory cost in KiB. Default 19_456 (19 MiB). FIPS preset uses 65_536. */
    memoryCost: number
    /** Time cost (iterations). Default 2. FIPS preset uses 3. */
    timeCost: number
    /** Parallelism. Default 1. FIPS preset uses 4. */
    parallelism: number
    /** Hash length in bytes. Default 32. */
    hashLength: number
    /** Salt length in bytes. Default 16. */
    saltLength: number
  }
}
