import { describe, expect, it } from 'vitest'
import { AuthScryptHasher } from '../scrypt'

describe('AuthScryptHasher', () => {
  // Cheap params so the suite runs in <1s on CI.
  const fast = new AuthScryptHasher({ N: 1 << 10, keylen: 32 })

  it('hash output is self-describing with scrypt$ prefix', async () => {
    const h = await fast.hash('correct horse battery staple')
    const parts = h.split('$')
    expect(parts[0]).toBe('scrypt')
    expect(parts).toHaveLength(6)
  })

  it('hash is unique per call (salt differs)', async () => {
    const a = await fast.hash('pw')
    const b = await fast.hash('pw')
    expect(a).not.toBe(b)
  })

  it('verify returns true for the right plaintext', async () => {
    const h = await fast.hash('pw-correct')
    expect(await fast.verify('pw-correct', h)).toBe(true)
  })

  it('verify returns false for the wrong plaintext', async () => {
    const h = await fast.hash('pw-correct')
    expect(await fast.verify('pw-wrong', h)).toBe(false)
  })

  it('verify returns false for a malformed hash without throwing', async () => {
    expect(await fast.verify('pw', 'not-a-scrypt-hash')).toBe(false)
    expect(await fast.verify('pw', '')).toBe(false)
    expect(await fast.verify('pw', 'scrypt$bad$bad$bad$bad$bad')).toBe(false)
  })

  it('needsRehash returns true for an older parameter set', async () => {
    const older = new AuthScryptHasher({ N: 1 << 10, keylen: 32 })
    const newer = new AuthScryptHasher({ N: 1 << 12, keylen: 32 })
    const h = await older.hash('pw')
    expect(newer.needsRehash(h)).toBe(true)
    expect(older.needsRehash(h)).toBe(false)
  })

  it('needsRehash returns true for malformed input (forces re-hash on read)', async () => {
    expect(fast.needsRehash('garbage')).toBe(true)
  })

  it('rejects non-power-of-two N during parse (defensive against tampering)', async () => {
    // Forge a hash with N=3 (not pow2). The parser refuses + verify returns false.
    const bogus = 'scrypt$3$8$1$YWJj$ZGVm'
    expect(await fast.verify('pw', bogus)).toBe(false)
  })
})
