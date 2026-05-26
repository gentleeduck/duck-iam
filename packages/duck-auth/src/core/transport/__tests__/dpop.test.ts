/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHash, createSign, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  bindPayloadToDPoP,
  computeJwkThumbprint,
  type DPoPClaims,
  type DPoPJsonWebKey,
  DPoPVerifier,
  MemoryDPoPNonceStore,
} from '../dpop'

interface KeyPair {
  publicJwk: DPoPJsonWebKey
  privateKey: KeyObject
}

function generateES256KeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return {
    publicJwk: publicKey.export({ format: 'jwk' }) as DPoPJsonWebKey,
    privateKey,
  }
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

function derToJoseEs256(der: Buffer): Buffer {
  // Minimal DER -> r||s decode for ES256 (P-256 = 32 byte halves).
  if (der[0] !== 0x30) throw new Error('not a DER sequence')
  let offset = 2
  if (der[1]! & 0x80) offset = 2 + (der[1]! & 0x7f)
  if (der[offset] !== 0x02) throw new Error('expected r INTEGER')
  const rLen = der[offset + 1]!
  let r = der.subarray(offset + 2, offset + 2 + rLen)
  offset = offset + 2 + rLen
  if (der[offset] !== 0x02) throw new Error('expected s INTEGER')
  const sLen = der[offset + 1]!
  let s = der.subarray(offset + 2, offset + 2 + sLen)
  // strip leading 0x00 padding from negative-bit guard
  if (r[0] === 0 && r.length === 33) r = r.subarray(1)
  if (s[0] === 0 && s.length === 33) s = s.subarray(1)
  // pad up to 32
  const rPad = Buffer.concat([Buffer.alloc(32 - r.length), r])
  const sPad = Buffer.concat([Buffer.alloc(32 - s.length), s])
  return Buffer.concat([rPad, sPad])
}

function mintDpopProof(kp: KeyPair, claims: Partial<DPoPClaims> & { htm: string; htu: string }): string {
  const header = {
    alg: 'ES256',
    typ: 'dpop+jwt',
    jwk: kp.publicJwk,
  }
  const payload: DPoPClaims = {
    jti: 'jti-' + Math.random().toString(36).slice(2),
    htm: claims.htm,
    htu: claims.htu,
    iat: claims.iat ?? Math.floor(Date.now() / 1000),
    ...(claims.ath !== undefined && { ath: claims.ath }),
    ...(claims.nonce !== undefined && { nonce: claims.nonce }),
  }
  const headerB64 = base64url(JSON.stringify(header))
  const payloadB64 = base64url(JSON.stringify(payload))
  const signingInput = `${headerB64}.${payloadB64}`
  const signer = createSign('SHA256')
  signer.update(signingInput)
  signer.end()
  const der = signer.sign(kp.privateKey)
  const sig = derToJoseEs256(der)
  return `${signingInput}.${base64url(sig)}`
}

describe('DPoPVerifier', () => {
  let verifier: DPoPVerifier
  let kp: KeyPair

  beforeEach(() => {
    verifier = new DPoPVerifier()
    kp = generateES256KeyPair()
  })

  it('accepts a well-formed ES256 proof for the request method + url', async () => {
    const proof = mintDpopProof(kp, { htm: 'POST', htu: 'https://api.test/resource' })
    const result = await verifier.verify(proof, {
      method: 'POST',
      url: 'https://api.test/resource',
    })
    expect(result.jkt).toBe(computeJwkThumbprint(kp.publicJwk))
  })

  it('rejects when htm differs from request method', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    await expect(verifier.verify(proof, { method: 'POST', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('rejects when htu differs from request url', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/wrong' })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/right' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('rejects on signature tampering', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    const parts = proof.split('.')
    const tampered = `${parts[0]}.${parts[1]}.${'A'.repeat(parts[2]!.length)}`
    await expect(verifier.verify(tampered, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('rejects a stale proof (outside freshness window)', async () => {
    const proof = mintDpopProof(kp, {
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000) - 600,
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('rejects replayed jti within freshness window', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    await verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('rejects proof missing typ=dpop+jwt', async () => {
    const header = { alg: 'ES256', typ: 'JWT', jwk: kp.publicJwk }
    const payload = {
      jti: 'x',
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000),
    }
    const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
    const signer = createSign('SHA256')
    signer.update(signingInput)
    signer.end()
    const sig = derToJoseEs256(signer.sign(kp.privateKey))
    const proof = `${signingInput}.${base64url(sig)}`
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('rejects proof carrying private key material (d component)', async () => {
    const jwk = { ...kp.publicJwk, d: 'BAD-SHOULD-NOT-BE-HERE' }
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk }
    const payload = {
      jti: 'x',
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000),
    }
    const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
    const signer = createSign('SHA256')
    signer.update(signingInput)
    signer.end()
    const sig = derToJoseEs256(signer.sign(kp.privateKey))
    const proof = `${signingInput}.${base64url(sig)}`
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH/DPOP_INVALID',
    })
  })

  it('verifies ath claim against supplied access token sha-256', async () => {
    const token = 'access-token-xyz'
    const ath = createHash('sha256').update(token).digest('base64url')
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x', ath })
    const result = await verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' }, token)
    expect(result.jkt).toBeTruthy()
  })

  it('rejects ath mismatch when access token supplied', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x', ath: 'wrong' })
    await expect(
      verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' }, 'access-token-xyz'),
    ).rejects.toMatchObject({ code: 'AUTH/DPOP_INVALID' })
  })

  it('htu normalization strips query + fragment', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    const result = await verifier.verify(proof, {
      method: 'GET',
      url: 'https://api.test/x?param=1#frag',
    })
    expect(result.jkt).toBeTruthy()
  })
})

describe('computeJwkThumbprint', () => {
  it('is deterministic across calls with the same JWK', () => {
    const jwk: DPoPJsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    }
    const a = computeJwkThumbprint(jwk)
    const b = computeJwkThumbprint(jwk)
    expect(a).toBe(b)
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('ignores property order in the input JWK (canonical EC ordering)', () => {
    const a = computeJwkThumbprint({
      kty: 'EC',
      crv: 'P-256',
      x: 'X',
      y: 'Y',
    })
    const b = computeJwkThumbprint({
      y: 'Y',
      crv: 'P-256',
      x: 'X',
      kty: 'EC',
    })
    expect(a).toBe(b)
  })

  it('refuses unsupported kty', () => {
    expect(() => computeJwkThumbprint({ kty: 'OCT' as unknown as 'EC' })).toThrow()
  })
})

describe('bindPayloadToDPoP', () => {
  it('appends cnf.jkt to a payload object without mutating other claims', () => {
    const payload = { sub: 'user-1', aud: 'app' }
    const bound = bindPayloadToDPoP(payload, 'jkt-1')
    expect(bound).toEqual({ sub: 'user-1', aud: 'app', cnf: { jkt: 'jkt-1' } })
  })
})

describe('MemoryDPoPNonceStore', () => {
  it('recordSeen returns true once, false on replay', async () => {
    const store = new MemoryDPoPNonceStore()
    expect(await store.recordSeen('jti-1', 60_000)).toBe(true)
    expect(await store.recordSeen('jti-1', 60_000)).toBe(false)
  })

  it('expired entries free up the jti for reuse', async () => {
    const store = new MemoryDPoPNonceStore()
    await store.recordSeen('jti-1', 10)
    await new Promise((r) => setTimeout(r, 15))
    expect(await store.recordSeen('jti-1', 60_000)).toBe(true)
  })
})
