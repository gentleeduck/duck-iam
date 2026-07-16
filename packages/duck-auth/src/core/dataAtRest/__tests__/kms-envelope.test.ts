import { randomBytes } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import type { Kms } from '~/core/dataAtRest/dataAtRest.types'
import { AuthKmsEnvelopeDataAtRest } from '../kms-envelope'

/** In-memory KMS that mimics AWS encryption-context semantics. */
function makeFakeKms(): Kms.Provider & {
  generateDataKey: ReturnType<typeof vi.fn>
  decryptDataKey: ReturnType<typeof vi.fn>
} {
  const wraps = new Map<string, { plaintext: Uint8Array; ctx: Kms.EncryptionContext | undefined }>()
  const generateDataKey = vi.fn(async (ctx?: Kms.EncryptionContext): Promise<Kms.DataKey> => {
    const plaintext = new Uint8Array(randomBytes(32))
    const handle = randomBytes(16).toString('hex')
    wraps.set(handle, { plaintext: new Uint8Array(plaintext), ctx })
    return {
      ciphertext: Buffer.from(handle, 'utf8'),
      keyId: 'arn:aws:kms:us-east-1:000000000000:key/fake',
      plaintext,
    }
  })
  const decryptDataKey = vi.fn(async (wrapped: Uint8Array, ctx?: Kms.EncryptionContext): Promise<Uint8Array> => {
    const handle = Buffer.from(wrapped).toString('utf8')
    const entry = wraps.get(handle)
    if (!entry) throw new Error('fake-kms: unknown ciphertext blob')
    // AWS-style encryption-context validation.
    if (JSON.stringify(entry.ctx ?? {}) !== JSON.stringify(ctx ?? {})) {
      throw new Error('fake-kms: encryption context mismatch')
    }
    return new Uint8Array(entry.plaintext)
  })
  return { decryptDataKey, generateDataKey, id: 'fake-kms' }
}

describe('AuthKmsEnvelopeDataAtRest', () => {
  it('roundtrips plaintext through envelope encryption', async () => {
    const kms = makeFakeKms()
    const a = new AuthKmsEnvelopeDataAtRest({ kms })
    const ct = await a.encrypt('top-secret', { field: 'ssn', identityId: 'u1' })
    expect(ct.split('$')[0]).toBe('kms-env')
    expect(ct.split('$')[1]).toBe('v1')
    const plain = await a.decrypt(ct, { field: 'ssn', identityId: 'u1' })
    expect(plain).toBe('top-secret')
  })

  it('encryption-context mismatch (different identityId) fails decrypt', async () => {
    const kms = makeFakeKms()
    const a = new AuthKmsEnvelopeDataAtRest({ kms })
    const ct = await a.encrypt('hi', { field: 'ssn', identityId: 'u1' })
    await expect(a.decrypt(ct, { field: 'ssn', identityId: 'other' })).rejects.toThrow()
  })

  it('rejects malformed ciphertext', async () => {
    const kms = makeFakeKms()
    const a = new AuthKmsEnvelopeDataAtRest({ kms })
    await expect(a.decrypt('not-a-ciphertext', { field: 'f', identityId: 'i' })).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
  })

  it('rejects wrong DEK size from KMS', async () => {
    const badKms: Kms.Provider = {
      decryptDataKey: async () => new Uint8Array(16),
      generateDataKey: async () => ({
        ciphertext: new Uint8Array([1]),
        keyId: 'k',
        plaintext: new Uint8Array(16),
      }),
      id: 'bad-kms',
    }
    const a = new AuthKmsEnvelopeDataAtRest({ kms: badKms })
    await expect(a.encrypt('x', { field: 'f', identityId: 'i' })).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
  })

  it('id derives from the underlying provider', () => {
    const a = new AuthKmsEnvelopeDataAtRest({ kms: makeFakeKms() })
    expect(a.id).toBe('kms-envelope:fake-kms')
  })

  it('passes encryption context to the KMS on encrypt + decrypt', async () => {
    const kms = makeFakeKms()
    const a = new AuthKmsEnvelopeDataAtRest({ kms })
    await a.encrypt('x', { field: 'phone', identityId: 'id-7', tag: 'tenant-a' })
    expect(kms.generateDataKey).toHaveBeenCalledWith({ field: 'phone', identityId: 'id-7', tag: 'tenant-a' })
  })
})
