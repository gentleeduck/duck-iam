import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Session } from '~/core/types/session'
import { AuthJwtTransport } from '../jwt.transport'

function fakeSession(): Session.Me {
  const now = Date.now()
  return {
    id: 'row-hash',
    identityId: 'user-1',
    kind: 'user',
    aal: 2,
    factors: [{ method: 'password', completedAt: new Date(now) }],
    tenantId: null,
    csrfHash: null,
    ip: null,
    userAgent: null,
    fingerprint: null,
    actingAs: null,
    createdAt: new Date(now),
    rotatedAt: new Date(now),
    expiresAt: new Date(now + 60_000),
    absoluteExpiresAt: new Date(now + 60_000),
    fresh: true,
  }
}

function findAccessToken(intents: ReturnType<AuthJwtTransport['issue']>): string {
  const json = intents.find((i) => i.type === 'json') as Extract<(typeof intents)[number], { type: 'json' }>
  return (json.body as { access_token: string }).access_token
}

describe('AuthJwtTransport - ES256', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const t = new AuthJwtTransport({
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
    const otherTransport = new AuthJwtTransport({
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

describe('AuthJwtTransport - RS256', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const t = new AuthJwtTransport({
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

describe('AuthJwtTransport - alg-confusion guard (RFC 8725 section 3.1)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

  it('rejects a token whose header alg differs from the key configured alg', async () => {
    // Use the ES256 key (configured alg=ES256) but forge a header
    // claiming HS256. Verify must reject without trying HMAC.
    const t = new AuthJwtTransport({
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
    const t = new AuthJwtTransport({
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

describe('AuthJwtTransport.jwks - HS256 keys never leak', () => {
  it('HS256-only config returns empty keys array', () => {
    const t = new AuthJwtTransport({
      signKey: { kid: 'k1', key: 'secret' },
      verifyKeys: [{ kid: 'k1', key: 'secret' }],
      issuer: 'https://app.example.com',
    })
    expect(t.jwks()).toEqual({ keys: [] })
  })
})

describe('AuthJwtTransport - EdDSA (Ed25519)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const t = new AuthJwtTransport({
    signKey: { kid: 'k-ed', alg: 'EdDSA', key: privPem },
    verifyKeys: [{ kid: 'k-ed', alg: 'EdDSA', key: pubPem }],
    issuer: 'https://app.example.com',
    ttlMs: 60_000,
  })

  it('issues an EdDSA JWT (header alg=EdDSA) + verifies round-trip', async () => {
    const intents = t.issue('plaintext-sid', fakeSession(), { fresh: true, absolute: false })
    const jwt = findAccessToken(intents)
    const [header] = jwt.split('.')
    const decoded = JSON.parse(Buffer.from(header!, 'base64url').toString('utf8'))
    expect(decoded.alg).toBe('EdDSA')
    expect(decoded.kid).toBe('k-ed')
    const session = await t.verify(jwt)
    expect(session?.identityId).toBe('user-1')
    expect(session?.aal).toBe(2)
  })

  it('rejects a forged token signed with a different ed25519 key', async () => {
    const other = generateKeyPairSync('ed25519')
    const forge = new AuthJwtTransport({
      signKey: { kid: 'k-ed', alg: 'EdDSA', key: other.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
      verifyKeys: [
        { kid: 'k-ed', alg: 'EdDSA', key: other.publicKey.export({ type: 'spki', format: 'pem' }).toString() },
      ],
      issuer: 'https://app.example.com',
    })
    const fakeJwt = findAccessToken(forge.issue('x', fakeSession(), { fresh: true, absolute: false }))
    expect(await t.verify(fakeJwt)).toBeNull()
  })

  it('jwks emits the OKP public key with crv=Ed25519', () => {
    const doc = t.jwks()
    expect(doc.keys).toHaveLength(1)
    const k = doc.keys[0] as Record<string, unknown>
    expect(k.kty).toBe('OKP')
    expect(k.crv).toBe('Ed25519')
    expect(k.alg).toBe('EdDSA')
    expect(k.use).toBe('sig')
    expect(k.kid).toBe('k-ed')
  })
})

describe('AuthJwtTransport.rotateSignKey - live JWKS rotation', () => {
  it('rotates the active sign kid; old verifyKey stays valid until retireVerifyKey', async () => {
    const a = generateKeyPairSync('ed25519')
    const b = generateKeyPairSync('ed25519')
    const aPriv = a.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    const aPub = a.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const bPriv = b.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    const bPub = b.publicKey.export({ type: 'spki', format: 'pem' }).toString()

    const t = new AuthJwtTransport({
      signKey: { kid: 'a', alg: 'EdDSA', key: aPriv },
      verifyKeys: [{ kid: 'a', alg: 'EdDSA', key: aPub }],
      issuer: 'https://app.example.com',
    })
    const t1 = findAccessToken(t.issue('x', fakeSession(), { fresh: true, absolute: false }))

    t.rotateSignKey({
      signKey: { kid: 'b', alg: 'EdDSA', key: bPriv },
      verifyKey: { kid: 'b', alg: 'EdDSA', key: bPub },
    })
    const t2 = findAccessToken(t.issue('x', fakeSession(), { fresh: true, absolute: false }))

    // Both tokens verify during overlap.
    expect((await t.verify(t1))?.identityId).toBe('user-1')
    expect((await t.verify(t2))?.identityId).toBe('user-1')

    // New tokens carry the new kid.
    const headerB = JSON.parse(Buffer.from(t2.split('.')[0]!, 'base64url').toString('utf8'))
    expect(headerB.kid).toBe('b')

    // After retiring 'a', the old token stops verifying.
    t.retireVerifyKey('a')
    expect(await t.verify(t1)).toBeNull()
  })

  it('refuses to retire the active signing kid', () => {
    const a = generateKeyPairSync('ed25519')
    const aPriv = a.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    const aPub = a.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const t = new AuthJwtTransport({
      signKey: { kid: 'a', alg: 'EdDSA', key: aPriv },
      verifyKeys: [{ kid: 'a', alg: 'EdDSA', key: aPub }],
      issuer: 'https://app.example.com',
    })
    expect(() => t.retireVerifyKey('a')).toThrow('AUTH_MISCONFIGURED')
  })

  it('HS256 rotation auto-syncs the verify entry from the signKey', async () => {
    const t = new AuthJwtTransport({
      signKey: { kid: 'k1', key: 'old-secret' },
      verifyKeys: [{ kid: 'k1', key: 'old-secret' }],
      issuer: 'https://app.example.com',
    })
    t.rotateSignKey({ signKey: { kid: 'k2', key: 'new-secret' } })
    const jwt = findAccessToken(t.issue('x', fakeSession(), { fresh: true, absolute: false }))
    expect((await t.verify(jwt))?.identityId).toBe('user-1')
  })
})
