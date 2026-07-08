import { AuthError } from '../errors'
import type { Kms } from '../types/infra'

/** Reference `Kms.IProvider` for AWS KMS. Lazy-loads `@aws-sdk/client-kms` (optional peer dep). */
export class AuthAwsKmsProvider implements Kms.Provider {
  readonly id = 'aws-kms'
  private readonly _keyId: string
  private readonly _client: AuthAwsKmsProvider.IKmsLike

  constructor(cfg: AuthAwsKmsProvider.IConfig) {
    this._keyId = cfg.keyId
    this._client = cfg.client
  }

  async generateDataKey(ctx?: Kms.EncryptionContext): Promise<Kms.DataKey> {
    const cmd = await loadCommand('GenerateDataKeyCommand')
    const out = (await this._client.send(
      new cmd({ KeyId: this._keyId, KeySpec: 'AES_256', EncryptionContext: ctx }),
    )) as AuthAwsKmsProvider.IGenerateDataKeyOutput
    if (!out.Plaintext || !out.CiphertextBlob) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'aws-kms',
        detail: 'GenerateDataKey returned no key material',
      })
    }
    return {
      plaintext: toUint8(out.Plaintext),
      ciphertext: toUint8(out.CiphertextBlob),
      keyId: out.KeyId ?? this._keyId,
    }
  }

  async decryptDataKey(wrapped: Uint8Array, ctx?: Kms.EncryptionContext): Promise<Uint8Array> {
    const cmd = await loadCommand('DecryptCommand')
    const out = (await this._client.send(
      new cmd({ CiphertextBlob: wrapped, EncryptionContext: ctx, KeyId: this._keyId }),
    )) as AuthAwsKmsProvider.IDecryptOutput
    if (!out.Plaintext) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'aws-kms',
        detail: 'Decrypt returned no plaintext',
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
      throw new AuthError('AUTH_MISCONFIGURED', {
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

export namespace AuthAwsKmsProvider {
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
