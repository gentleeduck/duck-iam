import { describe, expect, it } from 'vitest'
import { Argon2idHasher } from '../argon2'

/**
 * Detect whether `@node-rs/argon2` is installed without forcing CI to
 * carry the native dep. The peerDep is optional; when it is missing the
 * suite skips the integration-level tests and runs only the contract +
 * error-path tests that do not require the module.
 */
async function hasArgon2(): Promise<boolean> {
  try {
    await import('@node-rs/argon2' as string)
    return true
  } catch {
    return false
  }
}

describe('Argon2idHasher (contract)', () => {
  const hasher = new Argon2idHasher()

  it('exposes id = "argon2id"', () => {
    expect(hasher.id).toBe('argon2id')
  })

  it('verify returns false for non-argon2id input without throwing', async () => {
    expect(await hasher.verify('pw', 'scrypt$1$8$1$abc$def')).toBe(false)
    expect(await hasher.verify('pw', '')).toBe(false)
    expect(await hasher.verify('pw', '$argon2i$v=19$m=1,t=1,p=1$abc$def')).toBe(false)
  })

  it('needsRehash returns true for malformed input (forces upgrade on read)', () => {
    expect(hasher.needsRehash('garbage')).toBe(true)
    expect(hasher.needsRehash('')).toBe(true)
    expect(hasher.needsRehash('$argon2i$v=19$m=1,t=1,p=1$x$y')).toBe(true)
  })

  it('needsRehash parses m / t / p and compares against current params', () => {
    const newer = new Argon2idHasher({
      memoryCost: 30_000,
      timeCost: 3,
      parallelism: 2,
      hashLength: 32,
      saltLength: 16,
    })
    // Synthesized PHC string with deliberately-weaker params:
    const weak =
      '$argon2id$v=19$m=19456,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI'
    expect(newer.needsRehash(weak)).toBe(true)
  })

  it('hash() throws AUTH/MISCONFIGURED with install hint when peerDep is missing', async () => {
    const has = await hasArgon2()
    if (has) return // Skip - peer is installed, error path not reachable.
    await expect(hasher.hash('pw')).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })
})

// bun's test runner doesn't ship `describe.runIf`; fall back to `describe.skip`
// when the conditional helper is unavailable so the suite runs under both.
const _runIf = (vi: unknown, gate: boolean) => {
  const d = describe as unknown as {
    runIf?: (cond: boolean) => typeof describe
    skip: typeof describe
  }
  return typeof d.runIf === 'function' ? d.runIf(gate) : gate ? describe : d.skip
}
_runIf(undefined, await hasArgon2())('Argon2idHasher (integration; requires @node-rs/argon2)', () => {
  // Lowest legal params so the suite runs fast.
  const fast = new Argon2idHasher({
    memoryCost: 8,
    timeCost: 1,
    parallelism: 1,
    hashLength: 16,
    saltLength: 8,
  })

  it('hash produces a PHC string starting with $argon2id$', async () => {
    const h = await fast.hash('correct horse battery staple')
    expect(h.startsWith('$argon2id$')).toBe(true)
  })

  it('hash is unique per call (random salt)', async () => {
    const a = await fast.hash('pw')
    const b = await fast.hash('pw')
    expect(a).not.toBe(b)
  })

  it('verify true for the right plaintext, false for the wrong one', async () => {
    const h = await fast.hash('right')
    expect(await fast.verify('right', h)).toBe(true)
    expect(await fast.verify('wrong', h)).toBe(false)
  })

  it('needsRehash returns false for current params, true for upgraded params', async () => {
    const h = await fast.hash('pw')
    expect(fast.needsRehash(h)).toBe(false)
    const upgraded = new Argon2idHasher({
      memoryCost: 9,
      timeCost: 2,
      parallelism: 1,
      hashLength: 16,
      saltLength: 8,
    })
    expect(upgraded.needsRehash(h)).toBe(true)
  })
})
