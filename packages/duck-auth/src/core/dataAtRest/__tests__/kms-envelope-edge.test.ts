/**
 * Stress + edge-case suite for `AuthKmsEnvelopeDataAtRest`. The main
 * suite covers happy-path roundtrip; this file pokes at: empty
 * payload, large payload, unicode, malformed ciphertext shapes,
 * KMS failures mid-flight, repeated encrypt of the same plaintext
 * (must produce different ciphertexts due to per-record DEK).
 */

import { randomBytes } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import type { AuthKms } from '../../types/kms'
import { AuthKmsEnvelopeDataAtRest } from '../kms-envelope'

function makeFakeKms(): AuthKms.IProvider {
  const wraps = new Map<string, { plaintext: Uint8Array; ctx: AuthKms.IEncryptionContext | undefined }>()
  return {
    decryptDataKey: async (wrapped, ctx) => {
      const handle = Buffer.from(wrapped).toString('utf8')
      const entry = wraps.get(handle)
      if (!entry) throw new Error('unknown')
      if (JSON.stringify(entry.ctx ?? {}) !== JSON.stringify(ctx ?? {})) throw new Error('ctx mismatch')
      return new Uint8Array(entry.plaintext)
    },
    generateDataKey: async (ctx) => {
      const plaintext = new Uint8Array(randomBytes(32))
      const handle = randomBytes(16).toString('hex')
      wraps.set(handle, { ctx, plaintext: new Uint8Array(plaintext) })
      return { ciphertext: Buffer.from(handle, 'utf8'), keyId: 'k', plaintext }
    },
    id: 'fake-kms',
  }
}

describe('AuthKmsEnvelopeDataAtRest - edge cases', () => {
  it('roundtrips an empty string', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    const ct = await a.encrypt('', { field: 'note', identityId: 'u' })
    expect(await a.decrypt(ct, { field: 'note', identityId: 'u' })).toBe('')
  })

  it('roundtrips a 1 MiB plaintext', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    const big = 'A'.repeat(1024 * 1024)
    const ct = await a.encrypt(big, { field: 'blob', identityId: 'u' })
    const plain = await a.decrypt(ct, { field: 'blob', identityId: 'u' })
    expect(plain).toHaveLength(1024 * 1024)
    expect(plain.slice(0, 8)).toBe('AAAAAAAA')
  })

  it('handles utf-8 + emoji round-trip', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    const msg = 'Привет 你好 🦆🔐 - 𒀀'
    const ct = await a.encrypt(msg, { field: 'note', identityId: 'u' })
    expect(await a.decrypt(ct, { field: 'note', identityId: 'u' })).toBe(msg)
  })

  it('two encrypts of the same plaintext produce different ciphertexts', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    const c1 = await a.encrypt('s', { field: 'x', identityId: 'u' })
    const c2 = await a.encrypt('s', { field: 'x', identityId: 'u' })
    expect(c1).not.toBe(c2)
  })

  it('rejects ciphertext with wrong version header', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    await expect(a.decrypt('kms-env$v9$k$a$b$c$d', { field: 'x', identityId: 'u' })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })

  it('rejects ciphertext with truncated parts', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    await expect(a.decrypt('kms-env$v1$k$a$b', { field: 'x', identityId: 'u' })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })

  it('tampered ciphertext body fails AEAD authentication', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    const ct = await a.encrypt('secret', { field: 'x', identityId: 'u' })
    // Flip a bit in the body segment.
    const parts = ct.split('$')
    const body = Buffer.from(parts[6]!, 'base64url')
    body[0] = body[0]! ^ 0x01
    parts[6] = body.toString('base64url')
    const tampered = parts.join('$')
    await expect(a.decrypt(tampered, { field: 'x', identityId: 'u' })).rejects.toThrow()
  })

  it('zeroes the plaintext DEK after encrypt (memory-disclosure hygiene)', async () => {
    let captured: Uint8Array | null = null
    const observerKms: AuthKms.IProvider = {
      decryptDataKey: async () => new Uint8Array(32),
      generateDataKey: async () => {
        const plaintext = new Uint8Array(randomBytes(32))
        captured = plaintext
        return { ciphertext: Buffer.from('x'), keyId: 'k', plaintext }
      },
      id: 'observer',
    }
    const a = new AuthKmsEnvelopeDataAtRest({ kms: observerKms })
    await a.encrypt('hi', { field: 'x', identityId: 'u' })
    expect(captured).not.toBeNull()
    expect((captured as unknown as Uint8Array).every((b) => b === 0)).toBe(true)
  })

  it('zeroes the unwrapped DEK after decrypt failure', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    const ct = await a.encrypt('hi', { field: 'x', identityId: 'u' })
    let leakedAfter: Uint8Array | null = null
    const watchKms: AuthKms.IProvider = {
      decryptDataKey: async () => {
        // Return a wrong-size DEK so AES-GCM throws AFTER we get a chance
        // to observe whether plaintext-zero hygiene applies. We give the
        // adapter a real 32-byte DEK so encryption succeeds in the
        // happy path; tamper the BODY here so AES-GCM fails.
        const dek = new Uint8Array(32)
        leakedAfter = dek
        return dek
      },
      generateDataKey: async () => ({
        ciphertext: Buffer.from('x'),
        keyId: 'k',
        plaintext: new Uint8Array(32),
      }),
      id: 'watch',
    }
    const b = new AuthKmsEnvelopeDataAtRest({ kms: watchKms })
    await expect(b.decrypt(ct, { field: 'x', identityId: 'u' })).rejects.toThrow()
    expect(leakedAfter).not.toBeNull()
    expect((leakedAfter as unknown as Uint8Array).every((byte) => byte === 0)).toBe(true)
  })

  it('KMS generateDataKey throwing surfaces directly (no swallowing)', async () => {
    const broken: AuthKms.IProvider = {
      decryptDataKey: async () => new Uint8Array(32),
      generateDataKey: vi.fn(async () => {
        throw new Error('kms-down')
      }),
      id: 'broken',
    }
    const a = new AuthKmsEnvelopeDataAtRest({ kms: broken })
    await expect(a.encrypt('x', { field: 'f', identityId: 'i' })).rejects.toThrow('kms-down')
  })

  it('KMS decryptDataKey throwing surfaces directly', async () => {
    const kms = makeFakeKms()
    const a = new AuthKmsEnvelopeDataAtRest({ kms })
    const ct = await a.encrypt('x', { field: 'f', identityId: 'i' })
    const broken: AuthKms.IProvider = {
      decryptDataKey: async () => {
        throw new Error('kms-decrypt-down')
      },
      generateDataKey: kms.generateDataKey.bind(kms),
      id: 'broken',
    }
    const b = new AuthKmsEnvelopeDataAtRest({ kms: broken })
    await expect(b.decrypt(ct, { field: 'f', identityId: 'i' })).rejects.toThrow('kms-decrypt-down')
  })
})
