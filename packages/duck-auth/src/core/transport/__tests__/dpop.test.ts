import { createHash, createSign, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { bindPayloadToDPoP, computeJwkThumbprint, DPoPVerifier } from '../dpop.transport'
import { MemoryDPoPNonceStore } from '../dpop-nonce.memory'

interface KeyPair {
  publicJwk: DPoPVerifier.JsonWebKey
  privateKey: KeyObject
}

function generateES256KeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return {
    publicJwk: publicKey.export({ format: 'jwk' }) as DPoPVerifier.JsonWebKey,
    privateKey,
  }
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

function authDerToJoseEs256(der: Buffer): Buffer {
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

function mintDpopProof(kp: KeyPair, claims: Partial<DPoPVerifier.Claims> & { htm: string; htu: string }): string {
  const header = {
    alg: 'ES256',
    typ: 'dpop+jwt',
    jwk: kp.publicJwk,
  }
  const payload: DPoPVerifier.Claims = {
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
  const sig = authDerToJoseEs256(der)
  return `${signingInput}.${base64url(sig)}`
}

describe('AuthDPoPVerifier', () => {
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
      code: 'AUTH_DPOP_INVALID',
    })
  })

  it('rejects when htu differs from request url', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/wrong' })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/right' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
    })
  })

  it('rejects on signature tampering', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    const parts = proof.split('.')
    const tampered = `${parts[0]}.${parts[1]}.${'A'.repeat(parts[2]!.length)}`
    await expect(verifier.verify(tampered, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
    })
  })

  it('rejects a stale proof (outside freshness window)', async () => {
    const proof = mintDpopProof(kp, {
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000) - 600,
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
    })
  })

  it('rejects replayed jti within freshness window', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    await verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
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
    const sig = authDerToJoseEs256(signer.sign(kp.privateKey))
    const proof = `${signingInput}.${base64url(sig)}`
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
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
    const sig = authDerToJoseEs256(signer.sign(kp.privateKey))
    const proof = `${signingInput}.${base64url(sig)}`
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
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
    ).rejects.toMatchObject({ code: 'AUTH_DPOP_INVALID' })
  })

  it('rejects authed-request proof that omits ath (RFC 9449 §4.3)', async () => {
    // No ath in the proof, but the caller IS passing an access token.
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    await expect(
      verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' }, 'access-token-xyz'),
    ).rejects.toMatchObject({ code: 'AUTH_DPOP_INVALID', meta: { reason: 'ath required when access token present' } })
  })

  it('rejects a proof carrying ath when no access token is supplied (replay defense)', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x', ath: 'whatever' })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'ath unexpected (no access token in request)' },
    })
  })

  it('enforces expectedNonce when configured (RFC 9449 §8/9)', async () => {
    const v = new DPoPVerifier({ expectedNonce: 'srv-nonce-1' })
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x', nonce: 'wrong-nonce' })
    await expect(v.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'nonce mismatch' },
    })
  })

  it('passes when proof nonce matches expectedNonce', async () => {
    const v = new DPoPVerifier({ expectedNonce: 'srv-nonce-1' })
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x', nonce: 'srv-nonce-1' })
    const r = await v.verify(proof, { method: 'GET', url: 'https://api.test/x' })
    expect(r.jkt).toBeTruthy()
  })

  it('expectedNonce thunk lets ops rotate the challenge', async () => {
    let nonce = 'srv-nonce-old'
    const v = new DPoPVerifier({ expectedNonce: () => nonce })
    const proof1 = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x', nonce: 'srv-nonce-old' })
    await expect(v.verify(proof1, { method: 'GET', url: 'https://api.test/x' })).resolves.toBeDefined()
    // Rotate the nonce server-side; the old one no longer satisfies.
    nonce = 'srv-nonce-new'
    const proof2 = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/y', nonce: 'srv-nonce-old' })
    await expect(v.verify(proof2, { method: 'GET', url: 'https://api.test/y' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'nonce mismatch' },
    })
  })

  it('htu normalization strips query + fragment', async () => {
    const proof = mintDpopProof(kp, { htm: 'GET', htu: 'https://api.test/x' })
    const result = await verifier.verify(proof, {
      method: 'GET',
      url: 'https://api.test/x?param=1#frag',
    })
    expect(result.jkt).toBeTruthy()
  })

  // Claim-type strictness: ensures non-string/non-number iat/htm/htu
  // are rejected before NaN math or .toUpperCase()/new URL crashes.
  function mintWithRawClaims(payload: Record<string, unknown>): string {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: kp.publicJwk }
    const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
    const signer = createSign('SHA256')
    signer.update(signingInput)
    signer.end()
    const sig = authDerToJoseEs256(signer.sign(kp.privateKey))
    return `${signingInput}.${base64url(sig)}`
  }

  it('rejects a proof whose iat is missing (would bypass freshness via NaN math)', async () => {
    const proof = mintWithRawClaims({
      jti: 'jti-no-iat',
      htm: 'GET',
      htu: 'https://api.test/x',
      // iat intentionally omitted
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'iat missing or not a finite number' },
    })
  })

  it('rejects a proof whose iat is a string', async () => {
    const proof = mintWithRawClaims({
      jti: 'jti-str-iat',
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: String(Math.floor(Date.now() / 1000)),
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'iat missing or not a finite number' },
    })
  })

  it('rejects a proof whose htm is a non-string (would throw raw TypeError)', async () => {
    const proof = mintWithRawClaims({
      jti: 'jti-obj-htm',
      htm: { evil: 'object' },
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000),
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'htm missing or not a string' },
    })
  })

  it('rejects a proof whose htu is a non-string', async () => {
    const proof = mintWithRawClaims({
      jti: 'jti-obj-htu',
      htm: 'GET',
      htu: { evil: 'object' },
      iat: Math.floor(Date.now() / 1000),
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'htu missing or not a string' },
    })
  })

  it('rejects a proof whose ath is a non-string (would slip past identity-comparison check)', async () => {
    const proof = mintWithRawClaims({
      jti: 'jti-obj-ath',
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000),
      ath: { evil: 'object' },
    })
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'ath not a string' },
    })
  })

  it('rejects a proof whose nonce is a non-string', async () => {
    const v = new DPoPVerifier({ expectedNonce: 'srv-nonce-1' })
    const proof = mintWithRawClaims({
      jti: 'jti-obj-nonce',
      htm: 'GET',
      htu: 'https://api.test/x',
      iat: Math.floor(Date.now() / 1000),
      nonce: { evil: 'object' },
    })
    await expect(v.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'nonce not a string' },
    })
  })

  it('rejects a proof whose payload is a JSON array (not an object)', async () => {
    // Mint a proof whose payload encodes to a JSON array. Without the
    // `isPlainObject` parser guard, destructuring would yield all-undefined
    // claims and the verifier path would surface obscure errors.
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: kp.publicJwk }
    const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(['not', 'an', 'object']))}`
    const signer = createSign('SHA256')
    signer.update(signingInput)
    signer.end()
    const sig = authDerToJoseEs256(signer.sign(kp.privateKey))
    const proof = `${signingInput}.${base64url(sig)}`
    await expect(verifier.verify(proof, { method: 'GET', url: 'https://api.test/x' })).rejects.toMatchObject({
      code: 'AUTH_DPOP_INVALID',
      meta: { reason: 'malformed payload' },
    })
  })
})

describe('authComputeJwkThumbprint', () => {
  it('is deterministic across calls with the same JWK', () => {
    const jwk: DPoPVerifier.JsonWebKey = {
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

describe('authBindPayloadToDPoP', () => {
  it('appends cnf.jkt to a payload object without mutating other claims', () => {
    const payload = { sub: 'user-1', aud: 'app' }
    const bound = bindPayloadToDPoP(payload, 'jkt-1')
    expect(bound).toEqual({ sub: 'user-1', aud: 'app', cnf: { jkt: 'jkt-1' } })
  })
})

describe('AuthMemoryDPoPNonceStore', () => {
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

  it('prune is linear in expired-prefix (CPU DoS defense - 10k entries does not stall)', async () => {
    // The legacy prune iterated the entire map on every recordSeen,
    // turning each call under load into an O(N) sweep. With the
    // insertion-order break-on-non-expired loop, a typical call walks
    // only the freshly-expired prefix.
    const store = new MemoryDPoPNonceStore()
    // Seed 10k entries with the SAME short TTL - uniform TTL is the
    // contract under which the early-break is correct.
    for (let i = 0; i < 10_000; i++) {
      await store.recordSeen(`old-${i}`, 1)
    }
    // Let them all expire.
    await new Promise((r) => setTimeout(r, 5))
    // One-shot prune of 10k expired entries must finish under 200ms.
    const start = performance.now()
    expect(await store.recordSeen('fresh', 60_000)).toBe(true)
    const firstElapsed = performance.now() - start
    expect(firstElapsed).toBeLessThan(200)
    // A subsequent recordSeen should be O(1) - map is now empty plus
    // the single fresh entry which isn't yet expired (so the loop
    // immediately breaks).
    const start2 = performance.now()
    expect(await store.recordSeen('another-fresh', 60_000)).toBe(true)
    expect(performance.now() - start2).toBeLessThan(10)
  })

  it('stops pruning at the first non-expired entry (does not touch fresh entries)', async () => {
    // Construct: 3 fresh entries first, then attempt prune - the loop
    // must NOT delete them.
    const store = new MemoryDPoPNonceStore()
    await store.recordSeen('fresh-1', 60_000)
    await store.recordSeen('fresh-2', 60_000)
    await store.recordSeen('fresh-3', 60_000)
    // Trigger the prune via a recordSeen call.
    await store.recordSeen('trigger', 60_000)
    // All previously inserted jtis should still be marked as seen.
    expect(await store.recordSeen('fresh-1', 60_000)).toBe(false)
    expect(await store.recordSeen('fresh-2', 60_000)).toBe(false)
    expect(await store.recordSeen('fresh-3', 60_000)).toBe(false)
  })
})
