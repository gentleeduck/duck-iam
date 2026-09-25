/** For the compliance presets; needs the `@node-rs/argon2` peerDep. */

import { AuthError } from '~/core/errors'
import type { Hasher } from './hashers.types'

/** The namespace merge that puts `Argon2idHasher.Params` alongside the class. */
export namespace Argon2idHasher {
  export type Params = {
    /** Memory cost in KiB. Default 19_456, 19 MiB; the FIPS preset uses 65_536. */
    memoryCost: number
    /** Iterations. Default 2; the FIPS preset uses 3. */
    timeCost: number
    /** Default 1; the FIPS preset uses 4. */
    parallelism: number
    /** Hash length in bytes. Default 32. */
    hashLength: number
    /** Salt length in bytes. Default 16. */
    saltLength: number
  }
}

/** Conservative OWASP defaults. */
export const ARGON2ID_DEFAULTS: Argon2idHasher.Params = {
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
}

/** What the `fips` preset means by "Argon2id with FIPS params". Pass it explicitly -- no preset applies
 *  it for you -- and `AuthEngine.strict()` reads the result off {@link Argon2idHasher.__fipsParams}. */
export const ARGON2ID_COMPLIANCE: Argon2idHasher.Params = {
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
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'Argon2idHasher requires the @node-rs/argon2 peerDep. ' +
        'Install via `bun add @node-rs/argon2` (or `npm install @node-rs/argon2`).',
    })
  }
}

/** Lazy-imports `@node-rs/argon2` and encodes the PHC string
 *  `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`. */
export class Argon2idHasher implements Hasher.Me {
  readonly id = 'argon2id'
  private readonly _params: Argon2idHasher.Params

  /** Whether every parameter meets or exceeds `ARGON2ID_COMPLIANCE`, which is the `fipsValidatedHasher`
   *  compliance check. Read through `Reflect` by the passwords provider, so a foreign hasher that
   *  publishes nothing leaves that check to the operator's attestation rather than failing it. */
  readonly __fipsParams: boolean
  /** Below the floor `ARGON2ID_DEFAULTS` sets. Refused by `AuthEngine.strict()` in production only, since
   *  a cheap KDF is what a test suite wants and what a production deployment cannot have. */
  readonly __weakHasherParams: boolean

  constructor(params: Partial<Argon2idHasher.Params> = {}) {
    this._params = { ...ARGON2ID_DEFAULTS, ...params }
    // SECURITY: the work factor is the whole of a stored password's strength and arrived unchecked.
    // Measured: `{ memoryCost: 8, timeCost: 1 }` hashed and verified happily at 8 KiB and one pass, and
    // `needsRehash` - which compares a row against these very numbers - called the result current, so the
    // rehash-on-sign-in upgrade can never fire on a deployment that got them wrong. A non-integer threw
    // inside the native module on the first sign-up instead of here.
    for (const [name, value] of Object.entries(this._params)) {
      if (!Number.isInteger(value) || value < 1) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `argon2id: ${name} must be a whole number of at least 1, got ${String(value)}`,
        })
      }
    }
    if (this._params.hashLength < 16 || this._params.saltLength < 8) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `argon2id: hashLength must be at least 16 bytes and saltLength at least 8, got ${this._params.hashLength}/${this._params.saltLength}`,
      })
    }
    this.__weakHasherParams =
      this._params.memoryCost < ARGON2ID_DEFAULTS.memoryCost ||
      this._params.timeCost < ARGON2ID_DEFAULTS.timeCost ||
      this._params.hashLength < ARGON2ID_DEFAULTS.hashLength
    this.__fipsParams =
      this._params.memoryCost >= ARGON2ID_COMPLIANCE.memoryCost &&
      this._params.timeCost >= ARGON2ID_COMPLIANCE.timeCost &&
      this._params.parallelism >= ARGON2ID_COMPLIANCE.parallelism &&
      this._params.hashLength >= ARGON2ID_COMPLIANCE.hashLength &&
      this._params.saltLength >= ARGON2ID_COMPLIANCE.saltLength
  }

  /** Lazy-loads `@node-rs/argon2` on the first call. */
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

  /** Constant time, and `false` rather than a throw on malformed input. */
  async verify(plaintext: string, encoded: string): Promise<boolean> {
    if (!encoded.startsWith('$argon2id$')) return false
    // SECURITY: the load sits outside the catch, the verify is awaited inside it. Unawaited, the catch
    // never saw a rejection and a corrupt row threw where `false` is documented - telling itself apart
    // from a wrong password. Caught, `loadArgon2`'s install hint reached the user as "wrong password".
    const argon = await loadArgon2()
    try {
      return await argon.verify(encoded, plaintext)
    } catch {
      return false
    }
  }

  /** True when the stored hash used weaker params than the current set. The PHC string's `m=..,t=..,p=..`
   *  fields are compared independently, and weaker on any one of them is enough. */
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

/** Constructs an {@link Argon2idHasher}. */
export function argon2idHasher(...args: ConstructorParameters<typeof Argon2idHasher>): Argon2idHasher {
  return new Argon2idHasher(...args)
}
