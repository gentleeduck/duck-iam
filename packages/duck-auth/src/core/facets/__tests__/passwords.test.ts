import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { ScryptHasher } from '../../password/scrypt'
import { DEFAULT_PASSWORDS_CONFIG, PasswordsFacet } from '../passwords'

describe('PasswordsFacet', () => {
  let adapter: MemoryAuthAdapter
  let facet: PasswordsFacet
  const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })

  beforeEach(() => {
    adapter = new MemoryAuthAdapter()
    facet = new PasswordsFacet(adapter.credentials, fastHasher, DEFAULT_PASSWORDS_CONFIG)
  })

  describe('strength validation', () => {
    it('rejects passwords shorter than minLength as AUTH/INVALID_CREDENTIALS', async () => {
      await expect(facet.set('u', 'short')).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
    })

    it('rejects common passwords as AUTH/INVALID_CREDENTIALS', async () => {
      await expect(facet.set('u', 'password1')).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
    })

    it('common-list check is case-insensitive', async () => {
      await expect(facet.set('u', 'PASSWORD1')).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
    })

    it('rejects passwords longer than maxLength to prevent argon2/scrypt DoS', async () => {
      // A multi-megabyte "password" forces the hasher to process the
      // whole blob (several seconds of CPU per attempt). The cap stops
      // it at the strength gate, never reaching the hasher.
      const huge = 'x'.repeat(2048)
      await expect(facet.set('u', huge)).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
    })

    it('verify also rejects over-long plaintext (returns ok:false without hashing)', async () => {
      // Set a legitimate password first, then try to verify with a
      // pathologically long input. The verify path must short-circuit
      // before invoking the hasher.
      await facet.set('u', 'correct-horse-battery')
      const huge = 'x'.repeat(10_000)
      const r = await facet.verify('u', huge)
      expect(r.ok).toBe(false)
    })
  })

  describe('set + verify happy path', () => {
    it('set stores a hashed credential; verify returns ok for the right plaintext', async () => {
      await facet.set('user-1', 'correct-horse-battery')
      const r = await facet.verify('user-1', 'correct-horse-battery')
      expect(r.ok).toBe(true)
    })

    it('credential row has kind=password and algorithm metadata', async () => {
      await facet.set('user-1', 'correct-horse-battery')
      const rows = await adapter.credentials.listByIdentity('user-1', 'password', {})
      expect(rows).toHaveLength(1)
      expect(rows[0]?.kind).toBe('password')
      expect((rows[0]?.metadata as { algorithm: string }).algorithm).toBe('scrypt')
      expect(rows[0]?.secret.startsWith('scrypt$')).toBe(true)
    })

    it('set replaces any previous password credential', async () => {
      await facet.set('user-1', 'first-password')
      await facet.set('user-1', 'second-password')
      const rows = await adapter.credentials.listByIdentity('user-1', 'password', {})
      expect(rows).toHaveLength(1)
      const r = await facet.verify('user-1', 'second-password')
      expect(r.ok).toBe(true)
    })
  })

  describe('verify failure paths', () => {
    it('wrong password returns ok:false', async () => {
      await facet.set('user-1', 'right-password')
      const r = await facet.verify('user-1', 'wrong-password')
      expect(r.ok).toBe(false)
    })

    it('unknown identity returns ok:false (no enumeration timing)', async () => {
      const r = await facet.verify('ghost-user', 'whatever-pw')
      expect(r.ok).toBe(false)
    })

    it('revoked credential is ignored', async () => {
      await facet.set('user-1', 'password-1234')
      const rows = await adapter.credentials.listByIdentity('user-1', 'password', {})
      const row = rows[0]
      if (!row) throw new Error('expected a credential row')
      await adapter.credentials.revoke(row.id, {})
      const r = await facet.verify('user-1', 'password-1234')
      expect(r.ok).toBe(false)
    })
  })

  describe('needsRehash', () => {
    it('needsRehash=false when stored hash matches current params', async () => {
      await facet.set('user-1', 'password-1234')
      const r = await facet.verify('user-1', 'password-1234')
      expect(r.ok).toBe(true)
      if (r.ok) expect(r.needsRehash).toBe(false)
    })

    it('needsRehash=true when a stronger hasher is wired post-set', async () => {
      // First set with the fast (weak) hasher.
      await facet.set('user-1', 'password-1234')
      // Now wire a stronger hasher into a new facet and re-verify.
      const stronger = new ScryptHasher({ N: 1 << 12, keylen: 32 })
      const strongerFacet = new PasswordsFacet(adapter.credentials, stronger, DEFAULT_PASSWORDS_CONFIG)
      const r = await strongerFacet.verify('user-1', 'password-1234')
      expect(r.ok).toBe(true)
      if (r.ok) expect(r.needsRehash).toBe(true)
    })
  })

  describe('rehash()', () => {
    it('rehash replaces the existing hash with current params', async () => {
      await facet.set('user-1', 'password-1234')
      const beforeRows = await adapter.credentials.listByIdentity('user-1', 'password', {})
      const before = beforeRows[0]
      if (!before) throw new Error('expected credential row')

      const stronger = new ScryptHasher({ N: 1 << 12, keylen: 32 })
      const strongerFacet = new PasswordsFacet(adapter.credentials, stronger, DEFAULT_PASSWORDS_CONFIG)
      await strongerFacet.rehash('user-1', 'password-1234')

      const afterRows = await adapter.credentials.listByIdentity('user-1', 'password', {})
      const after = afterRows[0]
      if (!after) throw new Error('expected credential row after rehash')
      expect(after.secret).not.toBe(before.secret)
      // Stronger hasher should not request another rehash on its own output.
      expect(stronger.needsRehash(after.secret)).toBe(false)
    })

    it('rehash is a no-op when no credential exists', async () => {
      await expect(facet.rehash('ghost', 'whatever')).resolves.toBeUndefined()
    })
  })
})
