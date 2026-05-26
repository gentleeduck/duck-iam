/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Session } from '../../types/session'
import { JwtTransport } from '../jwt'

function fakeSession(): Session.ISession {
  const now = Date.now()
  return {
    id: 'row-hash',
    identityId: 'user-1',
    kind: 'user',
    aal: 2,
    factors: [{ method: 'password', completedAt: now }],
    createdAt: now,
    rotatedAt: now,
    expiresAt: now + 60_000,
    absoluteExpiresAt: now + 60_000,
    fresh: true,
  }
}

function findAccessToken(intents: ReturnType<JwtTransport['issue']>): string {
  const json = intents.find((i) => i.type === 'json') as Extract<(typeof intents)[number], { type: 'json' }>
  return (json.body as { access_token: string }).access_token
}

describe('JwtTransport - ES256', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const t = new JwtTransport({
    signKey: { kid: 'k-ec', alg: 'ES256', key: privPem },
    verifyKeys: [{ kid: 'k-ec', alg: 'ES256', key: pubPem }],
    issuer: 'https://app.example.com',
    ttlMs: 60_000,
  })

  it('issues an ES256 JWT (header alg=ES256) + verifies round-trip', async () => {
    const intents = t.issue('plaintext-sid', fakeSession(), { fresh: true, absolute: false })
    const jwt = findAccessToken(intents)
    const [header] = jwt.split('.')
    const decoded = JSON.parse(Buffer.from(header!, 'base64url').toString('utf8'))
    expect(decoded.alg).toBe('ES256')
    expect(decoded.kid).toBe('k-ec')
    const session = await t.verify(jwt)
    expect(session?.identityId).toBe('user-1')
    expect(session?.aal).toBe(2)
  })

  it('verify rejects a token signed by a different EC key', async () => {
    const intents = t.issue('plaintext-sid', fakeSession(), { fresh: true, absolute: false })
    const jwt = findAccessToken(intents)
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const otherTransport = new JwtTransport({
      signKey: {
        kid: 'k-ec',
        alg: 'ES256',
        key: other.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      },
      verifyKeys: [
        {
          kid: 'k-ec',
          alg: 'ES256',
          key: other.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      issuer: 'https://app.example.com',
    })
    expect(await otherTransport.verify(jwt)).toBeNull()
  })

  it('jwks emits the public key with kid + alg + use', () => {
    const doc = t.jwks()
    expect(doc.keys).toHaveLength(1)
    const k = doc.keys[0] as Record<string, unknown>
    expect(k.kid).toBe('k-ec')
    expect(k.alg).toBe('ES256')
    expect(k.use).toBe('sig')
    expect(k.kty).toBe('EC')
    expect(k.crv).toBe('P-256')
  })
})

describe('JwtTransport - RS256', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const t = new JwtTransport({
    signKey: { kid: 'k-rsa', alg: 'RS256', key: privPem },
    verifyKeys: [{ kid: 'k-rsa', alg: 'RS256', key: pubPem }],
    issuer: 'https://app.example.com',
    ttlMs: 60_000,
  })

  it('issues an RS256 JWT (header alg=RS256) + verifies round-trip', async () => {
    const intents = t.issue('plaintext-sid', fakeSession(), { fresh: true, absolute: false })
    const jwt = findAccessToken(intents)
    const [header] = jwt.split('.')
    const decoded = JSON.parse(Buffer.from(header!, 'base64url').toString('utf8'))
    expect(decoded.alg).toBe('RS256')
    const session = await t.verify(jwt)
    expect(session?.identityId).toBe('user-1')
  })

  it('jwks emits the RSA public key', () => {
    const doc = t.jwks()
    expect(doc.keys).toHaveLength(1)
    const k = doc.keys[0] as Record<string, unknown>
    expect(k.kty).toBe('RSA')
    expect(k.alg).toBe('RS256')
  })
})

describe('JwtTransport - alg-confusion guard (RFC 8725 section 3.1)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

  it('rejects a token whose header alg differs from the key configured alg', async () => {
    // Use the ES256 key (configured alg=ES256) but forge a header
    // claiming HS256. Verify must reject without trying HMAC.
    const t = new JwtTransport({
      signKey: { kid: 'k1', alg: 'ES256', key: privPem },
      verifyKeys: [{ kid: 'k1', alg: 'ES256', key: pubPem }],
      issuer: 'https://app.example.com',
    })
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'k1' })).toString('base64url')
    const payload = Buffer.from(
      JSON.stringify({
        iss: 'https://app.example.com',
        sub: 'user-1',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        sid: 'x',
        aal: 1,
        factors: ['password'],
      }),
    ).toString('base64url')
    // Sign with the PEM (as if attacker treated it as an HS256 key) -
    // verifier ignores the sig because alg mismatch is caught first.
    const fakeSig = 'A'.repeat(32)
    const jwt = `${header}.${payload}.${fakeSig}`
    expect(await t.verify(jwt)).toBeNull()
  })

  it('refuses unknown alg headers (none / RS512 / etc.)', async () => {
    const t = new JwtTransport({
      signKey: { kid: 'k1', key: 'secret' },
      verifyKeys: [{ kid: 'k1', key: 'secret' }],
      issuer: 'https://app.example.com',
    })
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: 'k1' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url')
    const jwt = `${header}.${payload}.`
    expect(await t.verify(jwt)).toBeNull()
  })
})

describe('JwtTransport.jwks - HS256 keys never leak', () => {
  it('HS256-only config returns empty keys array', () => {
    const t = new JwtTransport({
      signKey: { kid: 'k1', key: 'secret' },
      verifyKeys: [{ kid: 'k1', key: 'secret' }],
      issuer: 'https://app.example.com',
    })
    expect(t.jwks()).toEqual({ keys: [] })
  })
})
