/**
 * Every other length in this package that feeds a CSPRNG is bounded; the two that decide how expensive a
 * stored password is to crack were not, and the two failure modes are opposite and both silent.
 *
 * Measured before the guards. `scryptHasher({ keylen: 0 })` encoded a row with the key field blank and
 * `scryptHasher({ saltLen: 0 })` one with the salt field blank -- both of which `parse` refuses, because
 * an earlier finding hardened it against exactly such a row, so `hash` succeeded and `verify` answered
 * `false` to the correct password for ever after. In the other direction `{ N: 2 }` verified in 1.6ms
 * against the default's 940ms, `{ r: 0 }` and `{ p: 0 }` were accepted by Node and by `parse`, and
 * `argon2idHasher({ memoryCost: 8, timeCost: 1 })` hashed at 8 KiB and one pass -- with `needsRehash`,
 * which compares a row against these very numbers, calling each result current.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { passwords } from '../../passwords'
import { ARGON2ID_COMPLIANCE, ARGON2ID_DEFAULTS, argon2idHasher } from '../argon2'
import type { Hasher } from '../hashers.types'
import { SCRYPT_DEFAULTS, scryptHasher } from '../scrypt'

/** The refusal's `detail`, since `AuthError.message` is the bare code. */
function refusal(build: () => unknown): string {
  try {
    build()
    return 'constructed'
  } catch (err) {
    return (err as { meta: { detail: string } }).meta.detail
  }
}

describe('ScryptHasher refuses parameters that write a row its own reader rejects', () => {
  it.each([0, 1, 3, 12, Number.NaN, -1, 1.5])('N %s', (N) => {
    expect(refusal(() => scryptHasher({ N }))).toContain('N must be a power of two')
  })

  it.each([2 ** 25, 2 ** 53])('N %s is a power of two and still past what Node will allocate', (N) => {
    expect(refusal(() => scryptHasher({ N }))).toContain('maxmem both calls pass')
  })

  it.each([
    ['r', 0],
    ['r', Number.NaN],
    ['r', -1],
    ['r', 1.5],
    ['p', 0],
    ['p', Number.NaN],
  ] as const)('%s %s', (key, value) => {
    expect(refusal(() => scryptHasher({ [key]: value }))).toContain('r and p must be whole numbers')
  })

  it.each([0, 15, Number.NaN, -1, 32.5])('keylen %s', (keylen) => {
    expect(refusal(() => scryptHasher({ keylen }))).toContain('keylen must be a whole number of at least 16')
  })

  it.each([0, 7, Number.NaN, -1])('saltLen %s', (saltLen) => {
    expect(refusal(() => scryptHasher({ saltLen }))).toContain('saltLen must be a whole number of at least 8')
  })

  it('constructs on its own defaults and on the cheap set the test suite uses', () => {
    expect(refusal(() => scryptHasher())).toBe('constructed')
    expect(refusal(() => scryptHasher({ keylen: 32, N: 1 << 10 }))).toBe('constructed')
  })

  it('round-trips at the smallest shape it now allows, which is what used to lock the account out', async () => {
    const h = scryptHasher({ keylen: 16, N: 1 << 10, saltLen: 8 })
    const encoded = await h.hash('correct horse battery staple')
    expect(encoded.split('$').every((part) => part.length > 0)).toBe(true)
    expect(await h.verify('correct horse battery staple', encoded)).toBe(true)
    expect(await h.verify('nope', encoded)).toBe(false)
  })
})

describe('Argon2idHasher refuses a work factor that is not one', () => {
  it.each(['memoryCost', 'timeCost', 'parallelism', 'hashLength', 'saltLength'] as const)('%s at 0', (key) => {
    expect(refusal(() => argon2idHasher({ [key]: 0 }))).toContain(`${key} must be a whole number of at least 1`)
  })

  it.each([Number.NaN, -1, 2.5, Number.POSITIVE_INFINITY])('memoryCost %s', (memoryCost) => {
    expect(refusal(() => argon2idHasher({ memoryCost }))).toContain('memoryCost must be a whole number')
  })

  it.each([
    ['hashLength', 15],
    ['saltLength', 7],
  ] as const)('%s %s is above 1 and still too short', (key, value) => {
    expect(refusal(() => argon2idHasher({ [key]: value }))).toContain('hashLength must be at least 16 bytes')
  })

  it('constructs on its own defaults and on the compliance set', () => {
    expect(refusal(() => argon2idHasher())).toBe('constructed')
    expect(refusal(() => argon2idHasher(ARGON2ID_COMPLIANCE))).toBe('constructed')
  })
})

describe('what each hasher publishes about its own cost', () => {
  it.each([
    ['scrypt defaults', scryptHasher(), false],
    ['scrypt at the suite N', scryptHasher({ keylen: 32, N: 1 << 10 }), true],
    ['scrypt at N 2^14 and r 8', scryptHasher({ keylen: 32, N: 1 << 14 }), false],
    ['scrypt with r below 8', scryptHasher({ ...SCRYPT_DEFAULTS, r: 4 }), true],
    ['argon2 defaults', argon2idHasher(), false],
    ['argon2 at the FIPS set', argon2idHasher(ARGON2ID_COMPLIANCE), false],
    ['argon2 at 8 KiB and one pass', argon2idHasher({ memoryCost: 8, parallelism: 1, timeCost: 1 }), true],
    ['argon2 one KiB below its defaults', argon2idHasher({ ...ARGON2ID_DEFAULTS, memoryCost: 19_455 }), true],
  ] as const)('%s -> weak=%s', (_name, hasher, expected) => {
    expect(Reflect.get(hasher, '__weakHasherParams')).toBe(expected)
  })

  it('a foreign hasher publishes nothing, and the provider passes that through', () => {
    const foreign: Hasher.Me = { hash: async () => 'x', id: 'f', needsRehash: () => false, verify: async () => false }
    expect(Reflect.get(passwords({ hasher: foreign }), '__weakHasherParams')).toBeUndefined()
    expect(Reflect.get(passwords({ hasher: scryptHasher({ keylen: 32, N: 1 << 10 }) }), '__weakHasherParams')).toBe(
      true,
    )
  })
})

describe('strict() refuses a cheap KDF in production and nowhere else', () => {
  const NAMED = 'password hasher is configured below its own defaults'
  const engine = (hasher: Hasher.Me) => {
    const adapter = new MemoryAdapter()
    return new AuthEngine({
      baseUrl: 'https://app.test',
      providers: [passwords({ hasher })],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'sid', secure: true }),
    })
  }
  const complaints = (hasher: Hasher.Me, env: 'production' | 'test'): string => {
    try {
      engine(hasher).strict({ env })
      return ''
    } catch (err) {
      return (err as { meta: { detail: string } }).meta.detail
    }
  }

  it('names the hasher among the production complaints', () => {
    expect(complaints(scryptHasher({ keylen: 32, N: 1 << 10 }), 'production')).toContain(NAMED)
  })

  it('says nothing about it outside production, which is where a cheap KDF belongs', () => {
    expect(complaints(scryptHasher({ keylen: 32, N: 1 << 10 }), 'test')).not.toContain(NAMED)
  })

  it('says nothing about a hasher on its own defaults', () => {
    expect(complaints(scryptHasher(), 'production')).not.toContain(NAMED)
    expect(complaints(argon2idHasher(), 'production')).not.toContain(NAMED)
  })

  it('says nothing about a foreign hasher, whose cost it cannot read', () => {
    const foreign: Hasher.Me = { hash: async () => 'x', id: 'f', needsRehash: () => false, verify: async () => false }
    expect(complaints(foreign, 'production')).not.toContain(NAMED)
  })
})
