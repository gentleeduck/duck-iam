import { AuthError } from '../errors'
import type { Kms } from './dataAtRest.types'

/** Reference `Kms.Provider` for AWS KMS. Lazy-loads `@aws-sdk/client-kms` (optional peer dep). */
export class AuthAwsKmsProvider implements Kms.Provider {
  readonly id = 'aws-kms'
  private readonly _keyId: string
  private readonly _client: AuthAwsKmsProvider.IKmsLike

  constructor(cfg: AuthAwsKmsProvider.Cfg) {
    this._keyId = cfg.keyId
    this._client = cfg.client
  }

  /** One KMS round trip answering a fresh data key in both its plaintext and its wrapped form. */
  async generateDataKey(ctx?: Kms.EncryptionContext): Promise<Kms.DataKey> {
    const out = await this._client.send(
      await command('GenerateDataKeyCommand', { KeyId: this._keyId, KeySpec: 'AES_256', EncryptionContext: ctx }),
    )
    const keyId: unknown = typeof out === 'object' && out !== null ? Reflect.get(out, 'KeyId') : undefined
    return {
      plaintext: keyBytes(out, 'Plaintext', 'GenerateDataKey'),
      ciphertext: keyBytes(out, 'CiphertextBlob', 'GenerateDataKey'),
      keyId: typeof keyId === 'string' ? keyId : this._keyId,
    }
  }

  /** Unwraps a data key; the encryption context must match the one it was generated under. */
  async decryptDataKey(wrapped: Uint8Array, ctx?: Kms.EncryptionContext): Promise<Uint8Array> {
    const out = await this._client.send(
      await command('DecryptCommand', { CiphertextBlob: wrapped, EncryptionContext: ctx, KeyId: this._keyId }),
    )
    return keyBytes(out, 'Plaintext', 'Decrypt')
  }
}

let _kmsModule: Promise<object> | null = null
/** Builds an SDK command, loading `@aws-sdk/client-kms` on first use. */
async function command(name: 'GenerateDataKeyCommand' | 'DecryptCommand', input: object): Promise<unknown> {
  // Dynamic, so a host with no AWS workload never installs it: it is an optional peerDep.
  // @ts-expect-error -- optional peerDep, may not be installed.
  _kmsModule ??= import('@aws-sdk/client-kms').catch(() => {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'aws-kms: @aws-sdk/client-kms not installed. `bun add @aws-sdk/client-kms` to enable.',
    })
  })
  const Command: unknown = Reflect.get(await _kmsModule, name)
  if (typeof Command !== 'function') {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `aws-kms: @aws-sdk/client-kms exports no ${name}` })
  }
  return Reflect.construct(Command, [input])
}

/** A key field of a KMS response. The SDK answers bytes; anything else, a base64 string included, is none. */
function keyBytes(out: unknown, field: 'CiphertextBlob' | 'Plaintext', op: string): Uint8Array {
  const value: unknown = typeof out === 'object' && out !== null ? Reflect.get(out, field) : undefined
  if (value instanceof Uint8Array && value.length > 0) return value
  throw new AuthError('AUTH_PROVIDER_FAILED', { providerId: 'aws-kms', detail: `${op} returned no ${field} bytes` })
}

/** Configuration for the AWS KMS key provider, and the client surface it calls. */
export namespace AuthAwsKmsProvider {
  /** The one `KMSClient` method this provider calls. */
  export interface IKmsLike {
    /** Sends a KMS command, as `KMSClient.send` does. */
    send(command: unknown): Promise<unknown>
  }
  /** The KMS key and client the provider wraps data keys with. */
  export interface Cfg {
    /** KMS key id, ARN or alias, such as 'alias/duck-auth-data-at-rest'. */
    keyId: string
    /** A pre-configured KmsClient, or anything with a `send` method for tests. */
    client: IKmsLike
  }
}

/** Constructs an {@link AuthAwsKmsProvider}. */
export function authAwsKmsProvider(...args: ConstructorParameters<typeof AuthAwsKmsProvider>): AuthAwsKmsProvider {
  return new AuthAwsKmsProvider(...args)
}
