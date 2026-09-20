/** `Argon2idHasher` is what `DEFAULT_PASSWORDS_CONFIG` selects, and `@node-rs/argon2` is an *optional*
 *  peer dependency, so "the default hasher cannot load" is a state a real deployment reaches. The two
 *  methods disagreed about what it means: `hash` raised the error built to carry the install command,
 *  and `verify` - the one on the sign-in path - caught it and answered "wrong password". */

import { afterEach, describe, expect, it, vi } from 'vitest'

/** A real PHC string, so nothing short-circuits before the module is needed. */
const ENCODED = '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo'

/** A fresh module graph in which `@node-rs/argon2` cannot be imported. */
async function withoutArgon2() {
  vi.resetModules()
  vi.doMock('@node-rs/argon2', () => {
    throw new Error('Cannot find module')
  })
  const { Argon2idHasher } = await import('../argon2')
  return new Argon2idHasher()
}

afterEach(() => {
  vi.doUnmock('@node-rs/argon2')
  vi.resetModules()
})

describe('the default hasher with its optional peer dependency missing', () => {
  it('says so, with the install command, when hashing', async () => {
    const hasher = await withoutArgon2()
    await expect(hasher.hash('correct horse')).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
      meta: { detail: expect.stringContaining('@node-rs/argon2') },
    })
  })

  it('says the same when verifying, instead of reporting a wrong password', async () => {
    const hasher = await withoutArgon2()
    await expect(hasher.verify('correct horse', ENCODED)).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
      meta: { detail: expect.stringContaining('@node-rs/argon2') },
    })
  })

  it('still answers false for a hash from another algorithm, without reaching for the module', async () => {
    // The format check comes first, so a host that never configured argon2 can still hold scrypt rows.
    const hasher = await withoutArgon2()
    await expect(hasher.verify('correct horse', 'scrypt$131072$8$1$c2FsdA$a2V5')).resolves.toBe(false)
  })

  it('still reports needsRehash, which is string work the module is not needed for', async () => {
    const hasher = await withoutArgon2()
    expect(hasher.needsRehash('scrypt$131072$8$1$c2FsdA$a2V5')).toBe(true)
    expect(hasher.needsRehash(ENCODED)).toBe(false)
  })
})

describe('with the module present it still tells a wrong password from a broken install', () => {
  it('answers false for the wrong password and true for the right one', async () => {
    const { Argon2idHasher } = await import('../argon2')
    const hasher = new Argon2idHasher()
    const encoded = await hasher.hash('correct horse')

    await expect(hasher.verify('correct horse', encoded)).resolves.toBe(true)
    await expect(hasher.verify('wrong horse', encoded)).resolves.toBe(false)
  })

  it('answers false for a corrupt PHC string rather than raising a misconfiguration', async () => {
    const { Argon2idHasher } = await import('../argon2')
    await expect(new Argon2idHasher().verify('pw', '$argon2id$not-a-real-phc-string')).resolves.toBe(false)
  })
})
