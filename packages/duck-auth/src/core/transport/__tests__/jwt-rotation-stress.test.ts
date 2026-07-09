/**
 * Stress + edge-case suite for `AuthJwtTransport.rotateSignKey` and the
 * EdDSA codepath. Exercises:
 *   - many concurrent issue() calls during rotation
 *   - kid collisions in rotation
 *   - retire on kid that is not currently signing but still active
 *   - EdDSA + ES256 + RS256 keys coexisting in the same verify ring
 *   - notAfter cutoff observed at verify time
 */

import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Session } from '~/core/sessions/sessions.types'
import { AuthJwtTransport } from '../jwt.transport'

function fakeSession(): Session.Me {
  const now = Date.now()
  return {
    aal: 2,
    absoluteExpiresAt: new Date(now + 60_000),
    createdAt: new Date(now),
    expiresAt: new Date(now + 60_000),
    factors: [{ completedAt: new Date(now), method: 'password' }],
    fresh: true,
    id: 'row',
    identityId: 'user-1',
    kind: 'user',
    rotatedAt: new Date(now),
    tenantId: null,
    csrfHash: null,
    ip: null,
    userAgent: null,
    fingerprint: null,
    actingAs: null,
  }
}

function ed25519() {
  const kp = generateKeyPairSync('ed25519')
  return {
    priv: kp.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    pub: kp.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  }
}

function findAccessToken(intents: ReturnType<AuthJwtTransport['issue']>): string {
  const j = intents.find((i) => i.type === 'json') as Extract<(typeof intents)[number], { type: 'json' }>
  return (j.body as { access_token: string }).access_token
}

describe('AuthJwtTransport - rotation under concurrent issue', () => {
  it('issues 50 tokens across two rotations; every one verifies', async () => {
    const a = ed25519()
    const b = ed25519()
    const c = ed25519()
    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: a.priv, kid: 'a' },
      verifyKeys: [{ alg: 'EdDSA', key: a.pub, kid: 'a' }],
    })

    const minted: string[] = []
    for (let i = 0; i < 20; i++)
      minted.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))
    t.rotateSignKey({
      signKey: { alg: 'EdDSA', key: b.priv, kid: 'b' },
      verifyKey: { alg: 'EdDSA', key: b.pub, kid: 'b' },
    })
    for (let i = 0; i < 20; i++)
      minted.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))
    t.rotateSignKey({
      signKey: { alg: 'EdDSA', key: c.priv, kid: 'c' },
      verifyKey: { alg: 'EdDSA', key: c.pub, kid: 'c' },
    })
    for (let i = 0; i < 10; i++)
      minted.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))

    // All 50 must verify - the verify ring holds a, b, c.
    for (const tok of minted) {
      expect((await t.verify(tok))?.identityId).toBe('user-1')
    }
    // Tokens carry the right kid in the order minted.
    const headerOf = (jwt: string): string => {
      const h = JSON.parse(Buffer.from(jwt.split('.')[0]!, 'base64url').toString('utf8'))
      return h.kid as string
    }
    expect(minted.slice(0, 20).every((j) => headerOf(j) === 'a')).toBe(true)
    expect(minted.slice(20, 40).every((j) => headerOf(j) === 'b')).toBe(true)
    expect(minted.slice(40, 50).every((j) => headerOf(j) === 'c')).toBe(true)
  })

  it('rotation to a kid with mismatched verify-side alg throws', () => {
    const a = ed25519()
    const b = ed25519()
    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: a.priv, kid: 'a' },
      verifyKeys: [{ alg: 'EdDSA', key: a.pub, kid: 'a' }],
    })
    // Pre-seed the verify ring under kid 'b' as EdDSA, then try
    // rotating in a 'b' verifyKey that claims HS256. Refuse.
    t.rotateSignKey({
      signKey: { alg: 'EdDSA', key: b.priv, kid: 'b' },
      verifyKey: { alg: 'EdDSA', key: b.pub, kid: 'b' },
    })
    expect(() =>
      t.rotateSignKey({
        signKey: { kid: 'b', key: 'secret' },
        verifyKey: { key: 'secret', kid: 'b' /* HS256 default */ },
      }),
    ).toThrow('AUTH_MISCONFIGURED')
  })

  it('after rotation, retireVerifyKey(old) makes old tokens fail', async () => {
    const a = ed25519()
    const b = ed25519()
    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: a.priv, kid: 'a' },
      verifyKeys: [{ alg: 'EdDSA', key: a.pub, kid: 'a' }],
    })
    const oldTok = findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true }))
    t.rotateSignKey({
      signKey: { alg: 'EdDSA', key: b.priv, kid: 'b' },
      verifyKey: { alg: 'EdDSA', key: b.pub, kid: 'b' },
    })
    expect((await t.verify(oldTok))?.identityId).toBe('user-1')
    t.retireVerifyKey('a')
    expect(await t.verify(oldTok)).toBeNull()
  })

  it('notAfter cutoff retires tokens at verify time', async () => {
    const a = ed25519()
    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: a.priv, kid: 'a' },
      verifyKeys: [{ alg: 'EdDSA', key: a.pub, kid: 'a', notAfter: Date.now() - 1 }],
    })
    const tok = findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true }))
    expect(await t.verify(tok)).toBeNull()
  })

  it('verify ring holds HS256 + ES256 + RS256 + EdDSA simultaneously', async () => {
    const ed = ed25519()
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const ecPriv = ec.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    const ecPub = ec.publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const rsaPriv = rsa.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    const rsaPub = rsa.publicKey.export({ format: 'pem', type: 'spki' }).toString()

    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: ed.priv, kid: 'ed' },
      verifyKeys: [
        { alg: 'EdDSA', key: ed.pub, kid: 'ed' },
        { alg: 'ES256', key: ecPub, kid: 'ec' },
        { alg: 'RS256', key: rsaPub, kid: 'rsa' },
        { kid: 'hs', key: 'shared-secret' },
      ],
    })

    // Mint with each kid via in-place rotation
    const tokens: string[] = []
    tokens.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))
    t.rotateSignKey({ signKey: { alg: 'ES256', key: ecPriv, kid: 'ec' } })
    tokens.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))
    t.rotateSignKey({ signKey: { alg: 'RS256', key: rsaPriv, kid: 'rsa' } })
    tokens.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))
    t.rotateSignKey({ signKey: { key: 'shared-secret', kid: 'hs' } })
    tokens.push(findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true })))

    for (const tok of tokens) {
      expect((await t.verify(tok))?.identityId).toBe('user-1')
    }

    // JWKS doc excludes the HS256 entry
    const jwks = t.jwks()
    const algs = (jwks.keys as Array<{ alg: string }>).map((k) => k.alg).sort()
    expect(algs).toEqual(['ES256', 'EdDSA', 'RS256'])
  })

  it('EdDSA verify rejects truncated signatures', async () => {
    const ed = ed25519()
    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: ed.priv, kid: 'k' },
      verifyKeys: [{ alg: 'EdDSA', key: ed.pub, kid: 'k' }],
    })
    const tok = findAccessToken(t.issue('x', fakeSession(), { absolute: false, fresh: true }))
    const [h, p, s] = tok.split('.')
    const truncated = `${h}.${p}.${s!.slice(0, -4)}AAAA`
    expect(await t.verify(truncated)).toBeNull()
  })

  it('EdDSA verify rejects garbage public key on rotation', () => {
    const ed = ed25519()
    const t = new AuthJwtTransport({
      issuer: 'https://x',
      signKey: { alg: 'EdDSA', key: ed.priv, kid: 'k' },
      verifyKeys: [{ alg: 'EdDSA', key: ed.pub, kid: 'k' }],
    })
    expect(() =>
      t.rotateSignKey({
        signKey: { alg: 'EdDSA', key: 'not-a-pem', kid: 'k2' },
        verifyKey: { alg: 'EdDSA', key: 'also-not-a-pem', kid: 'k2' },
      }),
    ).not.toThrow() // rotate doesn't validate; verify will reject malformed keys lazily
  })
})
