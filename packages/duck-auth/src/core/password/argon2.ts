/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 *
 * Argon2id-backed password hasher. Compliance presets (HIPAA / SOC2 /
 * FIPS) require it; v0.1 default is the built-in scrypt because Argon2
 * needs the native `@node-rs/argon2` peerDep. Consumers wire this
 * hasher explicitly:
 *
 * ```ts
 * import { Argon2idHasher } from '@gentleduck/auth/core'
 * new AuthRoot({ passwords: { hasher: new Argon2idHasher() }, ... })
 * ```
 */

import { AuthErrorObject } from '../errors'
import type { Hasher } from '../types/hasher'

/**
 * Argon2id parameter set. Defaults match OWASP's "Memory-constrained
 * environments" guidance (m=19 MB, t=2, p=1) which is appropriate for
 * most server CPUs. Compliance presets ratchet to m=64 MB, t=3, p=4.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface Argon2idParams {
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

/** Conservative OWASP defaults. */
export const ARGON2ID_DEFAULTS: Argon2idParams = {
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
}

/** Tuned for compliance preset (HIPAA / SOC2 / FIPS). */
export const ARGON2ID_COMPLIANCE: Argon2idParams = {
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
        'Argon2idHasher requires the @node-rs/argon2 peerDep. ' +
        'Install via `bun add @node-rs/argon2` (or `npm install @node-rs/argon2`).',
    })
  }
}

/**
 * Argon2id hasher. v0.1 lazy-imports `@node-rs/argon2`; if the peerDep is
 * missing, the first hash() / verify() call throws AUTH/MISCONFIGURED
 * with install instructions. Compliance presets (HIPAA / SOC2 / FIPS)
 * wire this hasher and force the upgraded parameter set.
 *
 * Encoded format follows the standard Argon2 PHC string:
 *   `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`
 * self-describing across parameter rotations; `needsRehash` compares the
 * embedded `m / t / p` to the current params.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class Argon2idHasher implements Hasher.IHasher {
  readonly id = 'argon2id'
  private readonly _params: Argon2idParams

  constructor(params: Partial<Argon2idParams> = {}) {
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

/**
 * Namespace merge - Argon2idHasher.IParams alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace Argon2idHasher {
  /** Alias for the flat `Argon2idParams` type. */
  export type IParams = Argon2idParams
}
