import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { ScryptHasher } from '../../password/scrypt'
import type { Hasher } from '../../types/infra'
import { PasswordsFacet } from '../passwords'

interface VerifyCall {
  plaintext: string
  encoded: string
}

class SpyHasher implements Hasher.IHasher {
  readonly id = 'spy-scrypt'
  private readonly _inner: ScryptHasher
  readonly verifyCalls: VerifyCall[] = []
  readonly hashCalls: string[] = []

  constructor() {
    // Use small scrypt params so tests are fast but still exercise the
    // real encode/parse roundtrip (which is what the broken literal
    // tripped over).
    this._inner = new ScryptHasher({ N: 1 << 10, keylen: 32 })
  }

  async hash(plaintext: string): Promise<string> {
    this.hashCalls.push(plaintext)
    return this._inner.hash(plaintext)
  }

  async verify(plaintext: string, encoded: string): Promise<boolean> {
    this.verifyCalls.push({ plaintext, encoded })
    return this._inner.verify(plaintext, encoded)
  }

  needsRehash(encoded: string): boolean {
    return this._inner.needsRehash(encoded)
  }
}

describe('PasswordsFacet.verify - username-enumeration timing defense', () => {
  let adapter: MemoryAdapter
  let hasher: SpyHasher
  let facet: PasswordsFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    hasher = new SpyHasher()
    facet = new PasswordsFacet(adapter.credentials, hasher)
  })

  it('calls hasher.verify with a REAL encoded hash on the no-credential branch (not the broken `$$reference$$` literal)', async () => {
    const result = await facet.verify('ghost-identity', 'attempt-password-1234')
    expect(result.ok).toBe(false)
    expect(hasher.verifyCalls).toHaveLength(1)
    const { encoded } = hasher.verifyCalls[0]!
    // The reference passed to verify must be a real encoded scrypt
    // hash (6 `$`-split parts beginning with the scheme `scrypt`).
    const parts = encoded.split('$')
    expect(parts).toHaveLength(6)
    expect(parts[0]).toBe('scrypt')
    // Not the broken literal.
    expect(encoded).not.toBe('$$reference$$')
  })

  it('reuses the cached reference hash across multiple no-credential probes (only one hash() call total)', async () => {
    for (let i = 0; i < 5; i++) {
      await facet.verify(`ghost-${i}`, 'attempt-pw-1234')
    }
    expect(hasher.verifyCalls).toHaveLength(5)
    // All 5 used the SAME reference value.
    const refs = new Set(hasher.verifyCalls.map((c) => c.encoded))
    expect(refs.size).toBe(1)
    // hash() was called exactly once (on first miss) - not 5 times.
    expect(hasher.hashCalls).toHaveLength(1)
    expect(hasher.hashCalls[0]).toBe('duck-auth:no-credential-reference')
  })

  it('uses the row.secret (not the reference) on the existing-credential branch', async () => {
    await facet.set('identity-1', 'correct-horse-battery-staple')
    // hash() called once during `set()`.
    expect(hasher.hashCalls).toHaveLength(1)

    // Wrong-password attempt; verify SHOULD pass row.secret (not the
    // reference) to the hasher.
    const result = await facet.verify('identity-1', 'wrong-password')
    expect(result.ok).toBe(false)
    expect(hasher.verifyCalls).toHaveLength(1)
    const { encoded } = hasher.verifyCalls[0]!
    const parts = encoded.split('$')
    expect(parts).toHaveLength(6)
    expect(parts[0]).toBe('scrypt')
    // The reference hash was NEVER computed for this branch (no
    // additional hash() call past the initial set).
    expect(hasher.hashCalls).toHaveLength(1)
  })

  it('correct password still succeeds (no regression on the happy path)', async () => {
    await facet.set('identity-1', 'correct-horse-battery-staple')
    const result = await facet.verify('identity-1', 'correct-horse-battery-staple')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.needsRehash).toBe(false)
    }
  })

  it('no-credential verify and wrong-password verify both go through hasher.verify exactly once', async () => {
    // This is the timing-defense invariant: the count of hasher.verify
    // calls must be IDENTICAL between the two branches. Earlier
    // implementations that bailed early (no hasher call) revealed
    // identity existence by call-count alone (and by wall-clock).
    await facet.set('identity-1', 'a-real-pw')
    hasher.verifyCalls.length = 0 // reset counter

    await facet.verify('identity-1', 'wrong')
    const realBranchCalls = hasher.verifyCalls.length

    await facet.verify('ghost-identity', 'wrong')
    const ghostBranchCalls = hasher.verifyCalls.length - realBranchCalls

    expect(realBranchCalls).toBe(1)
    expect(ghostBranchCalls).toBe(1)
  })
})
