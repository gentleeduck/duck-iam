/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { describe, expect, it } from 'vitest'
import { AesGcmDataAtRest } from '../aes-gcm'

describe('AesGcmDataAtRest', () => {
  const masterKey = Buffer.alloc(32, 1) // 32 bytes of 0x01
  const adapter = new AesGcmDataAtRest({ kid: 'k1', masterKey })

  it('encrypt + decrypt roundtrip succeeds for the same context', async () => {
    const ct = await adapter.encrypt('top-secret', { field: 'ssn', identityId: 'u' })
    const plain = await adapter.decrypt(ct, { field: 'ssn', identityId: 'u' })
    expect(plain).toBe('top-secret')
  })

  it('ciphertext format is self-describing aes-256-gcm$kid$iv$tag$ct', async () => {
    const ct = await adapter.encrypt('hi', { field: 'f', identityId: 'i' })
    const parts = ct.split('$')
    expect(parts).toHaveLength(5)
    expect(parts[0]).toBe('aes-256-gcm')
    expect(parts[1]).toBe('k1')
  })

  it('different (field, identityId) contexts derive different DEKs - decryption fails', async () => {
    const ct = await adapter.encrypt('s', { field: 'ssn', identityId: 'u' })
    await expect(adapter.decrypt(ct, { field: 'ssn', identityId: 'other' })).rejects.toThrow()
    await expect(adapter.decrypt(ct, { field: 'phone', identityId: 'u' })).rejects.toThrow()
  })

  it('tampered ciphertext fails AEAD verification', async () => {
    const ct = await adapter.encrypt('hi', { field: 'f', identityId: 'i' })
    const tampered = `${ct.slice(0, -3)}xxx`
    await expect(adapter.decrypt(tampered, { field: 'f', identityId: 'i' })).rejects.toThrow()
  })

  it('needsReEncrypt is false for current kid, true for older kid', async () => {
    const ct = await adapter.encrypt('x', { field: 'f', identityId: 'i' })
    expect(adapter.needsReEncrypt(ct)).toBe(false)
    const olderKidCt = ct.replace('$k1$', '$k0$')
    expect(adapter.needsReEncrypt(olderKidCt)).toBe(true)
  })

  it('refuses constructor with masterKey shorter than 32 bytes', () => {
    expect(() => new AesGcmDataAtRest({ kid: 'k', masterKey: Buffer.alloc(16) })).toThrow()
  })

  it('id is stable for audit-log reporting', () => {
    expect(adapter.id).toBe('aes-256-gcm')
  })
})
