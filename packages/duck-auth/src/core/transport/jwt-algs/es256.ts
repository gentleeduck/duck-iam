/**
 * ES256: ECDSA-P256-SHA256 sign + verify with DER<->JOSE conversion.
 *
 * Node's createSign/createVerify use DER; JOSE wire format is the raw
 * r||s pair (64 bytes for P-256). The two helpers handle the conversion.
 */

import { createSign, createVerify } from 'node:crypto'

export function authSignEs256(key: string, signingInput: string): string {
  const signer = createSign('SHA256')
  signer.update(signingInput)
  signer.end()
  return authDerToJoseEs256(signer.sign(key)).toString('base64url')
}

export function authVerifyEs256(key: string, signingInput: string, sigB64: string): boolean {
  const verifier = createVerify('SHA256')
  verifier.update(signingInput)
  verifier.end()
  try {
    return verifier.verify(key, authJoseToDerEs256(Buffer.from(sigB64, 'base64url')))
  } catch {
    return false
  }
}

export function authDerToJoseEs256(der: Buffer): Buffer {
  const halfLen = 32
  if (der[0] !== 0x30) throw new Error('ES256 sig: not a DER sequence')
  let offset = 2
  if ((der[1] ?? 0) & 0x80) offset = 2 + ((der[1] ?? 0) & 0x7f)
  if (der[offset] !== 0x02) throw new Error('ES256 sig: expected r INTEGER')
  const rLen = der.readUInt8(offset + 1)
  let r = der.subarray(offset + 2, offset + 2 + rLen)
  offset = offset + 2 + rLen
  if (der[offset] !== 0x02) throw new Error('ES256 sig: expected s INTEGER')
  const sLen = der.readUInt8(offset + 1)
  let s = der.subarray(offset + 2, offset + 2 + sLen)
  if (r[0] === 0 && r.length === halfLen + 1) r = r.subarray(1)
  if (s[0] === 0 && s.length === halfLen + 1) s = s.subarray(1)
  return Buffer.concat([Buffer.alloc(halfLen - r.length), r, Buffer.alloc(halfLen - s.length), s])
}

export function authJoseToDerEs256(raw: Buffer): Buffer {
  const halfLen = 32
  if (raw.length !== halfLen * 2) throw new Error('ES256 sig: bad length')
  let r = raw.subarray(0, halfLen)
  let s = raw.subarray(halfLen)
  while (r.length > 1 && r[0] === 0) r = r.subarray(1)
  while (s.length > 1 && s[0] === 0) s = s.subarray(1)
  const rEnc = (r.readUInt8(0) & 0x80) === 0 ? r : Buffer.concat([Buffer.from([0]), r])
  const sEnc = (s.readUInt8(0) & 0x80) === 0 ? s : Buffer.concat([Buffer.from([0]), s])
  return Buffer.concat([
    Buffer.from([0x30, rEnc.length + sEnc.length + 4]),
    Buffer.from([0x02, rEnc.length]),
    rEnc,
    Buffer.from([0x02, sEnc.length]),
    sEnc,
  ])
}
