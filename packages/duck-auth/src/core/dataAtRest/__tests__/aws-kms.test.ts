import { randomBytes } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { AwsKmsProvider } from '../aws-kms'
import { KmsEnvelopeDataAtRest } from '../kms-envelope'

/** Mock `KmsClient.send` that matches the AWS SDK call shape. */
function makeClient() {
  // Map from CiphertextBlob (string-encoded) -> { plaintext, ctx }
  const wraps = new Map<string, { plaintext: Uint8Array; ctx: Record<string, string> | undefined }>()
  return {
    send: vi.fn(async (cmd: { __cmd: string; input: Record<string, unknown> }) => {
      if (cmd.__cmd === 'GenerateDataKeyCommand') {
        const plaintext = new Uint8Array(randomBytes(32))
        const blob = randomBytes(16)
        wraps.set(blob.toString('hex'), {
          ctx: cmd.input.EncryptionContext as Record<string, string> | undefined,
          plaintext: new Uint8Array(plaintext),
        })
        return { CiphertextBlob: blob, KeyId: 'k1', Plaintext: plaintext }
      }
      if (cmd.__cmd === 'DecryptCommand') {
        const blob = cmd.input.CiphertextBlob as Uint8Array
        const key = Buffer.from(blob).toString('hex')
        const entry = wraps.get(key)
        if (!entry) throw new Error('NotFound')
        if (JSON.stringify(entry.ctx ?? {}) !== JSON.stringify(cmd.input.EncryptionContext ?? {})) {
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

describe('AwsKmsProvider (with mocked @aws-sdk/client-kms)', () => {
  it('generateDataKey returns plaintext + ciphertext + keyId', async () => {
    const client = makeClient()
    const p = new AwsKmsProvider({ client, keyId: 'alias/duck' })
    const dek = await p.generateDataKey({ field: 'ssn', identityId: 'u1' })
    expect(dek.plaintext).toHaveLength(32)
    expect(dek.ciphertext.length).toBeGreaterThan(0)
    expect(dek.keyId).toBe('k1')
  })

  it('end-to-end with KmsEnvelopeDataAtRest', async () => {
    const client = makeClient()
    const provider = new AwsKmsProvider({ client, keyId: 'alias/duck' })
    const a = new KmsEnvelopeDataAtRest({ kms: provider })
    const ct = await a.encrypt('hello', { field: 'phone', identityId: 'u1' })
    const plain = await a.decrypt(ct, { field: 'phone', identityId: 'u1' })
    expect(plain).toBe('hello')
  })

  it('forwards EncryptionContext to AWS', async () => {
    const client = makeClient()
    const p = new AwsKmsProvider({ client, keyId: 'alias/duck' })
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
