import { describe, expect, it } from 'vitest'
import { ScryptHasher } from '../scrypt'

describe('AuthScryptHasher', () => {
  // Cheap params so the suite runs in <1s on CI.
  const fast = new ScryptHasher({ N: 1 << 10, keylen: 32 })

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
    const older = new ScryptHasher({ N: 1 << 10, keylen: 32 })
    const newer = new ScryptHasher({ N: 1 << 12, keylen: 32 })
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

  describe('a stored hash carrying no key material', () => {
    // `scrypt` with a keylen of 0 answers an empty buffer instead of throwing, and `timingSafeEqual`
    // calls two empty buffers equal - so the length the verifier derives is taken from the stored row
    // and a row whose key field is gone asks for a zero-length comparison that nothing can fail.
    // A truncated column or a half-finished write is enough to produce one.
    const noKey = 'scrypt$16384$8$1$c2FsdHNhbHRzYWx0$'

    it('does not verify an arbitrary password against it', async () => {
      const hasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
      expect(await hasher.verify('not the password', noKey)).toBe(false)
    })

    it('does not verify an empty password against it either', async () => {
      const hasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
      expect(await hasher.verify('', noKey)).toBe(false)
    })

    it('refuses one with no salt as well', async () => {
      const hasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
      expect(await hasher.verify('anything', 'scrypt$16384$8$1$$a2V5')).toBe(false)
    })

    it('asks for a rehash rather than reading as usable', async () => {
      const hasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
      expect(hasher.needsRehash(noKey)).toBe(true)
    })

    it('a real hash still verifies, so the guard is the empty key and not the format', async () => {
      const hasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
      const encoded = await hasher.hash('correct-horse-battery')
      expect(await hasher.verify('correct-horse-battery', encoded)).toBe(true)
      expect(await hasher.verify('wrong', encoded)).toBe(false)
    })
  })
})
