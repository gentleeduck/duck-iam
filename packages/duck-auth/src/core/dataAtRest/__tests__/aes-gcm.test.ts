import { describe, expect, it } from 'vitest'
import { AuthAesGcmDataAtRest } from '../aes-gcm'

const tagMismatch = { code: 'AUTH_INVALID_PARAMETERS', meta: { detail: expect.stringContaining('auth-tag mismatch') } }

describe('AuthAesGcmDataAtRest', () => {
  const masterKey = Buffer.alloc(32, 1) // 32 bytes of 0x01
  const adapter = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey })

  it('encrypt + decrypt roundtrip succeeds for the same context', async () => {
    const ct = await adapter.encrypt('top-secret', { field: 'ssn', identityId: 'u' })
    const plain = await adapter.decrypt(ct, { field: 'ssn', identityId: 'u' })
    expect(plain).toBe('top-secret')
  })

  it('ciphertext format is self-describing alg$kid$iv$tag$ct', async () => {
    const ct = await adapter.encrypt('hi', { field: 'f', identityId: 'i' })
    const parts = ct.split('$')
    expect(parts).toHaveLength(5)
    expect(parts[0]).toBe('aes-256-gcm.v2')
    expect(parts[1]).toBe('k1')
  })

  it('different (field, identityId) contexts derive different DEKs - decryption fails', async () => {
    const ct = await adapter.encrypt('s', { field: 'ssn', identityId: 'u' })
    // The tag, not just a throw: a bare assertion would pass on a missing key or a short IV too and stop
    // saying anything about the derivation.
    await expect(adapter.decrypt(ct, { field: 'ssn', identityId: 'other' })).rejects.toMatchObject(tagMismatch)
    await expect(adapter.decrypt(ct, { field: 'phone', identityId: 'u' })).rejects.toMatchObject(tagMismatch)
  })

  it('tampered ciphertext fails AEAD verification', async () => {
    const ct = await adapter.encrypt('hi', { field: 'f', identityId: 'i' })
    // Same length and still five segments, so this reaches `final()` rather than being turned away as
    // malformed - which is what makes it a test of the tag.
    const tampered = `${ct.slice(0, -3)}xxx`
    await expect(adapter.decrypt(tampered, { field: 'f', identityId: 'i' })).rejects.toMatchObject(tagMismatch)
  })

  it('needsReEncrypt is false for current kid, true for older kid', async () => {
    const ct = await adapter.encrypt('x', { field: 'f', identityId: 'i' })
    expect(adapter.needsReEncrypt(ct)).toBe(false)
    const olderKidCt = ct.replace('$k1$', '$k0$')
    expect(adapter.needsReEncrypt(olderKidCt)).toBe(true)
  })

  it('refuses constructor with masterKey shorter than 32 bytes', () => {
    expect(() => new AuthAesGcmDataAtRest({ kid: 'k', masterKey: Buffer.alloc(16) })).toThrowError(
      expect.objectContaining({ meta: { detail: expect.stringContaining('>= 32 bytes') } }),
    )
  })

  it('id is stable for audit-log reporting', () => {
    expect(adapter.id).toBe('aes-256-gcm')
  })

  it('rotation - previousKeys ring decrypts ciphertexts written under an older kid', async () => {
    // Adapter v1: kid=k1
    const v1 = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: Buffer.alloc(32, 1) })
    const ct = await v1.encrypt('secret-payload', { field: 'ssn', identityId: 'u' })

    // Adapter v2: rotated to k2, with k1 retained for backwards compat.
    const v2 = new AuthAesGcmDataAtRest({
      kid: 'k2',
      masterKey: Buffer.alloc(32, 2),
      previousKeys: [{ kid: 'k1', masterKey: Buffer.alloc(32, 1) }],
    })
    const recovered = await v2.decrypt(ct, { field: 'ssn', identityId: 'u' })
    expect(recovered).toBe('secret-payload')

    // After re-encrypting, the ciphertext is tagged with the new kid.
    expect(v2.needsReEncrypt(ct)).toBe(true)
    const reEncrypted = await v2.encrypt(recovered, { field: 'ssn', identityId: 'u' })
    expect(reEncrypted.split('$')[1]).toBe('k2')
    expect(v2.needsReEncrypt(reEncrypted)).toBe(false)
  })

  it('rotation - ciphertext under an unknown kid throws AUTH/MISCONFIGURED (not silent data loss)', async () => {
    const v1 = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: Buffer.alloc(32, 1) })
    const ct = await v1.encrypt('payload', { field: 'f', identityId: 'u' })
    const v2 = new AuthAesGcmDataAtRest({ kid: 'k2', masterKey: Buffer.alloc(32, 2) })
    await expect(v2.decrypt(ct, { field: 'f', identityId: 'u' })).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
      meta: { detail: expect.stringContaining('not in key ring') },
    })
  })

  it('rotation - duplicate kid between current + previousKeys throws at construction', () => {
    try {
      new AuthAesGcmDataAtRest({
        kid: 'k1',
        masterKey: Buffer.alloc(32, 1),
        previousKeys: [{ kid: 'k1', masterKey: Buffer.alloc(32, 9) }],
      })
      throw new Error('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH_MISCONFIGURED')
      expect((err as { meta: { detail: string } }).meta.detail).toMatch(/duplicate kid/)
    }
  })
})
