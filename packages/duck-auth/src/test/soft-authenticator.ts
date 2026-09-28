import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server'
import { isoCBOR } from '@simplewebauthn/server/helpers'

/** An ECDSA authenticator in software, so a test runs the real `@simplewebauthn/server` verifier. */
export type SoftAuthenticator = {
  /** The credential id, base64url, as the browser reports it. */
  id: string
  /** The COSE public key, base64url, as a stored credential row carries it. */
  publicKey: string
  /** Attestation `none`, at signature count 0. */
  register(challenge: string): RegistrationResponseJSON
  /** `forged` signs other bytes, as a party without the key has to; `verified: false` asserts presence alone,
   *  as a security key with no PIN does. */
  assert(challenge: string, count: number, opts?: { forged?: boolean; verified?: boolean }): AuthenticationResponseJSON
}

const sha256 = (data: Uint8Array | string): Buffer => createHash('sha256').update(data).digest()

/** COSE `alg` and `crv` per curve, the hash its signatures use, and a coordinate's size in bytes. */
const CURVES = {
  'P-256': { alg: -7, crv: 1, hash: 'sha256', size: 32 },
  'P-521': { alg: -36, crv: 3, hash: 'sha512', size: 66 },
}

const count32 = (count: number): Buffer => {
  const out = Buffer.alloc(4)
  out.writeUInt32BE(count)
  return out
}

/** `id` is the credential id to claim, base64url, a fresh random one by default; `curve` is P-256 (ES256)
 *  by default. */
export function softAuthenticator(
  rpID: string,
  origin: string,
  { id = randomBytes(16).toString('base64url'), curve = 'P-256' }: { id?: string; curve?: keyof typeof CURVES } = {},
): SoftAuthenticator {
  const { alg, crv, hash, size } = CURVES[curve]
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: curve })
  // An EC SPKI ends in the uncompressed point: x, then y.
  const point = publicKey.export({ format: 'der', type: 'spki' }).subarray(-2 * size)
  const coseKey = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, alg],
      [-1, crv],
      [-2, new Uint8Array(point.subarray(0, size))],
      [-3, new Uint8Array(point.subarray(size))],
    ]),
  )
  const rawId = Buffer.from(id, 'base64url')
  const clientData = (type: string, challenge: string): Buffer =>
    Buffer.from(JSON.stringify({ type, challenge, origin }))

  return {
    id,
    publicKey: Buffer.from(coseKey).toString('base64url'),
    register(challenge) {
      // Flags 0x45: user present, user verified, attested credential data. Then the aaguid, all zero.
      const authData = Buffer.concat([
        sha256(rpID),
        Buffer.from([0x45]),
        count32(0),
        Buffer.alloc(16),
        Buffer.from([rawId.length >> 8, rawId.length & 0xff]),
        rawId,
        coseKey,
      ])
      const attestationObject = isoCBOR.encode(
        new Map<string, string | Uint8Array | Map<string, string>>([
          ['fmt', 'none'],
          ['attStmt', new Map<string, string>()],
          ['authData', new Uint8Array(authData)],
        ]),
      )
      return {
        clientExtensionResults: {},
        id,
        rawId: id,
        response: {
          attestationObject: Buffer.from(attestationObject).toString('base64url'),
          clientDataJSON: clientData('webauthn.create', challenge).toString('base64url'),
          transports: ['internal'],
        },
        type: 'public-key',
      }
    },
    assert(challenge, count, { forged = false, verified = true } = {}) {
      // Flags 0x05: user present, user verified; 0x01: present alone.
      const authData = Buffer.concat([sha256(rpID), Buffer.from([verified ? 0x05 : 0x01]), count32(count)])
      const clientDataJSON = clientData('webauthn.get', challenge)
      const signed = forged ? Buffer.from('not this assertion') : Buffer.concat([authData, sha256(clientDataJSON)])
      return {
        clientExtensionResults: {},
        id,
        rawId: id,
        response: {
          authenticatorData: authData.toString('base64url'),
          clientDataJSON: clientDataJSON.toString('base64url'),
          signature: sign(hash, signed, privateKey).toString('base64url'),
        },
        type: 'public-key',
      }
    },
  }
}
