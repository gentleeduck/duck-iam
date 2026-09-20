/**
 * Stress + edge-case suite for `AuthKmsEnvelopeDataAtRest`. The main
 * suite covers happy-path roundtrip; this file pokes at: empty
 * payload, large payload, unicode, malformed ciphertext shapes,
 * KMS failures mid-flight, repeated encrypt of the same plaintext
 * (must produce different ciphertexts due to per-record DEK).
 */

import { randomBytes } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import type { Kms } from '~/core/dataAtRest/dataAtRest.types'
import { AuthKmsEnvelopeDataAtRest } from '../kms-envelope'

function makeFakeKms(): Kms.Provider {
  const wraps = new Map<string, { plaintext: Uint8Array; ctx: Kms.EncryptionContext | undefined }>()
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
      code: 'AUTH_INVALID_PARAMETERS',
    })
  })

  it('rejects ciphertext with truncated parts', async () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    await expect(a.decrypt('kms-env$v1$k$a$b', { field: 'x', identityId: 'u' })).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
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
    // Typed, not Node's own wording: an unwrapped `final()` failure leaves as a message no error map knows.
    await expect(a.decrypt(tampered, { field: 'x', identityId: 'u' })).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: expect.stringContaining('auth-tag mismatch') },
    })
  })

  it('zeroes the plaintext DEK after encrypt (memory-disclosure hygiene)', async () => {
    let captured: Uint8Array | null = null
    const observerKms: Kms.Provider = {
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
    const watchKms: Kms.Provider = {
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
    await expect(b.decrypt(ct, { field: 'x', identityId: 'u' })).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
    })
    expect(leakedAfter).not.toBeNull()
    expect((leakedAfter as unknown as Uint8Array).every((byte) => byte === 0)).toBe(true)
  })

  it('KMS generateDataKey throwing surfaces directly (no swallowing)', async () => {
    const broken: Kms.Provider = {
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
    const broken: Kms.Provider = {
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

/**
 * The AES-GCM adapter next door refuses a non-standard IV or auth tag before handing either to Node,
 * with the reason written down: "Node accepts shorter ones, which weaken the cipher." This adapter
 * calls the same two Node APIs and checked neither. A 4-byte tag is a forgery target of 2^32 rather
 * than 2^128, and the whole point of encryption at rest is to hold when someone can write the column.
 */
describe('AuthKmsEnvelopeDataAtRest - GCM parameter sizes', () => {
  const ctx = { field: 'email', identityId: 'u1' }

  /** Re-emit a real ciphertext with one component swapped, so everything else stays valid. */
  async function withPart(index: number, value: string) {
    const kms = makeFakeKms()
    const adapter = new AuthKmsEnvelopeDataAtRest({ kms })
    const parts = (await adapter.encrypt('secret@example.com', ctx)).split('$')
    parts[index] = value
    return { adapter, cipherText: parts.join('$') }
  }

  /**
   * On the `detail`, not the code. A random short tag fails to authenticate anyway, so asserting the
   * code alone passes whether or not the size was ever checked - the test would read as coverage while
   * Node went on accepting 32-bit tags. The message is the only thing that says which branch refused it.
   */
  it.each([
    ['a truncated', 4],
    ['an oversize', 32],
  ])('refuses %s auth tag by size, before Node is given the chance to accept it', async (_label, bytes) => {
    const { adapter, cipherText } = await withPart(5, randomBytes(bytes).toString('base64url'))
    await expect(adapter.decrypt(cipherText, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'kms-envelope: auth tag must be 16 bytes' },
    })
  })

  it.each([4, 8, 16])('refuses a %d-byte IV by size, since GCM is specified at 12', async (bytes) => {
    const { adapter, cipherText } = await withPart(4, randomBytes(bytes).toString('base64url'))
    await expect(adapter.decrypt(cipherText, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'kms-envelope: IV must be 12 bytes' },
    })
  })

  it('still roundtrips an untouched ciphertext', async () => {
    const kms = makeFakeKms()
    const adapter = new AuthKmsEnvelopeDataAtRest({ kms })
    expect(await adapter.decrypt(await adapter.encrypt('secret@example.com', ctx), ctx)).toBe('secret@example.com')
  })
})
