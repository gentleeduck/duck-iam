import { AuthErrorObject } from '../errors'
import type { Kms } from '../types/kms'

/**
 * Reference `Kms.IProvider` for AWS KMS. Lazy-loads
 * `@aws-sdk/client-kms` so AWS SDK is an OPTIONAL peerDep - the rest
 * of duck-auth never pulls it in. Wire this into
 * `KmsEnvelopeDataAtRest` to get production-grade field-level
 * encryption against a real KMS.
 *
 * The two calls map onto the AWS API one-to-one:
 *   - `generateDataKey` -> `GenerateDataKey` with `KeySpec=AES_256`
 *   - `decryptDataKey`  -> `Decrypt`
 *
 * Encryption context is forwarded directly to AWS, which validates
 * it on Decrypt (CIPHER-MISMATCH on any drift). The default behavior
 * follows AWS' guidance - bind the wrapped DEK to the record it
 * protects so leaking a single ciphertext does not let an attacker
 * unwrap DEKs for other rows.
 *
 * Usage:
 *
 *     import { KmsClient } from '@aws-sdk/client-kms'
 *     const provider = new AwsKmsProvider({
 *       keyId: 'alias/duck-auth-data-at-rest',
 *       client: new KmsClient({ region: 'us-east-1' }),
 *     })
 *     const dataAtRest = new KmsEnvelopeDataAtRest({ kms: provider })
 *
 * For unit tests, pass a mock `IKmsLike` via `cfg.client`.
 */
export class AwsKmsProvider implements Kms.IProvider {
  readonly id = 'aws-kms'
  private readonly _keyId: string
  private readonly _client: AwsKmsProvider.IKmsLike

  constructor(cfg: AwsKmsProvider.IConfig) {
    this._keyId = cfg.keyId
    this._client = cfg.client
  }

  async generateDataKey(ctx?: Kms.IEncryptionContext): Promise<Kms.IDataKey> {
    const cmd = await loadCommand('GenerateDataKeyCommand')
    const out = (await this._client.send(
      new cmd({ KeyId: this._keyId, KeySpec: 'AES_256', EncryptionContext: ctx }),
    )) as AwsKmsProvider.IGenerateDataKeyOutput
    if (!out.Plaintext || !out.CiphertextBlob) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        detail: 'aws-kms: GenerateDataKey returned no key material',
      })
    }
    return {
      plaintext: toUint8(out.Plaintext),
      ciphertext: toUint8(out.CiphertextBlob),
      keyId: out.KeyId ?? this._keyId,
    }
  }

  async decryptDataKey(wrapped: Uint8Array, ctx?: Kms.IEncryptionContext): Promise<Uint8Array> {
    const cmd = await loadCommand('DecryptCommand')
    const out = (await this._client.send(
      new cmd({ CiphertextBlob: wrapped, EncryptionContext: ctx, KeyId: this._keyId }),
    )) as AwsKmsProvider.IDecryptOutput
    if (!out.Plaintext) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        detail: 'aws-kms: Decrypt returned no plaintext',
      })
    }
    return toUint8(out.Plaintext)
  }
}

let _kmsModule: { GenerateDataKeyCommand: unknown; DecryptCommand: unknown } | null = null
async function loadCommand<K extends 'GenerateDataKeyCommand' | 'DecryptCommand'>(
  name: K,
): Promise<new (input: unknown) => unknown> {
  if (!_kmsModule) {
    try {
      // dynamic import so consumers without AWS workloads never
      // pay the @aws-sdk install cost. The package is an OPTIONAL
      // peerDep declared in package.json.
      // @ts-expect-error -- optional peerDep, may not be installed.
      _kmsModule = (await import('@aws-sdk/client-kms')) as unknown as {
        GenerateDataKeyCommand: unknown
        DecryptCommand: unknown
      }
    } catch {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'aws-kms: @aws-sdk/client-kms not installed. `bun add @aws-sdk/client-kms` to enable.',
      })
    }
  }
  return _kmsModule[name] as new (
    input: unknown,
  ) => unknown
}

function toUint8(v: Uint8Array | Buffer | ArrayBuffer): Uint8Array {
  if (v instanceof Uint8Array) return v
  return new Uint8Array(v as ArrayBuffer)
}

/**
 * Namespace merge for AwsKmsProvider.
 */
export namespace AwsKmsProvider {
  export interface IKmsLike {
    send(command: unknown): Promise<unknown>
  }
  export interface IConfig {
    /** KMS key id, ARN, or alias (e.g., 'alias/duck-auth-data-at-rest'). */
    keyId: string
    /** A pre-configured KmsClient (or any object with a `send` method, for tests). */
    client: IKmsLike
  }
  export interface IGenerateDataKeyOutput {
    Plaintext?: Uint8Array | Buffer
    CiphertextBlob?: Uint8Array | Buffer
    KeyId?: string
  }
  export interface IDecryptOutput {
    Plaintext?: Uint8Array | Buffer
    KeyId?: string
  }
}
