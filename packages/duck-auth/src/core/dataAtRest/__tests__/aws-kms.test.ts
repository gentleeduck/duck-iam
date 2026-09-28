import { randomBytes } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { AuthAwsKmsProvider } from '../aws-kms'
import { AuthKmsEnvelopeDataAtRest } from '../kms-envelope'

/** Mock `KmsClient.send` that matches the AWS SDK call shape. */
function makeClient() {
  // Map from CiphertextBlob (string-encoded) -> { plaintext, ctx }
  const wraps = new Map<string, { plaintext: Uint8Array; ctx: string }>()
  return {
    send: vi.fn(async (cmd: { __cmd: string; input: Record<string, unknown> }) => {
      if (cmd.__cmd === 'GenerateDataKeyCommand') {
        const plaintext = new Uint8Array(randomBytes(32))
        const blob = randomBytes(16)
        wraps.set(blob.toString('hex'), {
          ctx: JSON.stringify(cmd.input.EncryptionContext ?? {}),
          plaintext: new Uint8Array(plaintext),
        })
        return { CiphertextBlob: blob, KeyId: 'k1', Plaintext: plaintext }
      }
      if (cmd.__cmd === 'DecryptCommand') {
        const blob = cmd.input.CiphertextBlob
        if (!(blob instanceof Uint8Array)) throw new Error('CiphertextBlob is not bytes')
        const key = Buffer.from(blob).toString('hex')
        const entry = wraps.get(key)
        if (!entry) throw new Error('NotFound')
        if (entry.ctx !== JSON.stringify(cmd.input.EncryptionContext ?? {})) {
          throw new Error('CtxMismatch')
        }
        return { KeyId: 'k1', Plaintext: entry.plaintext }
      }
      throw new Error(`unknown command ${cmd.__cmd}`)
    }),
  }
}

// Hoist the mock so `import('@aws-sdk/client-kms')` inside aws-kms.ts resolves.
vi.mock('@aws-sdk/client-kms', () => ({
  DecryptCommand: class {
    __cmd = 'DecryptCommand'
    constructor(public input: unknown) {}
  },
  GenerateDataKeyCommand: class {
    __cmd = 'GenerateDataKeyCommand'
    constructor(public input: unknown) {}
  },
}))

describe('AuthAwsKmsProvider (with mocked @aws-sdk/client-kms)', () => {
  it('generateDataKey returns plaintext + ciphertext + keyId', async () => {
    const client = makeClient()
    const p = new AuthAwsKmsProvider({ client, keyId: 'alias/duck' })
    const dek = await p.generateDataKey({ field: 'ssn', identityId: 'u1' })
    expect(dek.plaintext).toHaveLength(32)
    expect(dek.ciphertext.length).toBeGreaterThan(0)
    expect(dek.keyId).toBe('k1')
  })

  it('end-to-end with AuthKmsEnvelopeDataAtRest', async () => {
    const client = makeClient()
    const provider = new AuthAwsKmsProvider({ client, keyId: 'alias/duck' })
    const a = new AuthKmsEnvelopeDataAtRest({ kms: provider })
    const ct = await a.encrypt('hello', { field: 'phone', identityId: 'u1' })
    const plain = await a.decrypt(ct, { field: 'phone', identityId: 'u1' })
    expect(plain).toBe('hello')
  })

  it('refuses a wrapped key that is not bytes, which the envelope would store unwrappable', async () => {
    const kms = (CiphertextBlob: unknown) =>
      new AuthAwsKmsProvider({
        client: { send: async () => ({ CiphertextBlob, KeyId: 'k1', Plaintext: new Uint8Array(randomBytes(32)) }) },
        keyId: 'alias/duck',
      })
    for (const blob of ['AQIDBA==', new Uint8Array(0), undefined]) {
      await expect(kms(blob).generateDataKey()).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    }
    await expect(kms(new Uint8Array([1, 2, 3, 4])).generateDataKey()).resolves.toMatchObject({ keyId: 'k1' })
  })

  it('refuses an unwrapped key that is not bytes', async () => {
    const kms = (Plaintext: unknown) =>
      new AuthAwsKmsProvider({ client: { send: async () => ({ Plaintext }) }, keyId: 'alias/duck' })
    await expect(kms('AQIDBA==').decryptDataKey(new Uint8Array([1]))).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    await expect(kms(new Uint8Array(32)).decryptDataKey(new Uint8Array([1]))).resolves.toHaveLength(32)
  })

  it('forwards EncryptionContext to AWS', async () => {
    const client = makeClient()
    const p = new AuthAwsKmsProvider({ client, keyId: 'alias/duck' })
    await p.generateDataKey({ field: 'ssn', identityId: 'u1' })
    expect(client.send).toHaveBeenCalledWith(
      expect.objectContaining({
        __cmd: 'GenerateDataKeyCommand',
        input: expect.objectContaining({
          EncryptionContext: { field: 'ssn', identityId: 'u1' },
          KeyId: 'alias/duck',
          KeySpec: 'AES_256',
        }),
      }),
    )
  })
})
