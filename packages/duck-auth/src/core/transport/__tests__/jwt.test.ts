import { describe, expect, it } from 'vitest'
import type { Session } from '../../types/session'
import { JwtTransport } from '../jwt'

function fakeSession(overrides: Partial<Session.ISession> = {}): Session.ISession {
  const now = Date.now()
  return {
    id: 'row-hash',
    identityId: 'user-1',
    kind: 'user',
    aal: 2,
    factors: [
      { method: 'password', completedAt: now },
      { method: 'totp', completedAt: now },
    ],
    createdAt: now,
    rotatedAt: now,
    expiresAt: now + 60_000,
    absoluteExpiresAt: now + 60_000,
    fresh: true,
    ...overrides,
  }
}

describe('JwtTransport', () => {
  const baseCfg = {
    signKey: { kid: 'k1', key: 'super-secret-key-for-tests-only' },
    verifyKeys: [{ kid: 'k1', key: 'super-secret-key-for-tests-only' }],
    issuer: 'https://app.example.com',
    ttlMs: 60_000,
  }

  describe('issue + verify roundtrip', () => {
    it('issues a JWT in the json intent + verify reconstructs the session', async () => {
      const t = new JwtTransport(baseCfg)
      const session = fakeSession()
      const intents = t.issue('plain-sid', session, { fresh: true, absolute: false })
      const jsonIntent = intents.find((i) => i.type === 'json')
      expect(jsonIntent).toBeDefined()
      const body = (jsonIntent as { body: { access_token: string } }).body
      expect(body.access_token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)

      const back = await t.verify(body.access_token)
      expect(back?.identityId).toBe('user-1')
      expect(back?.aal).toBe(2)
      expect(back?.factors.map((f) => f.method).sort()).toEqual(['password', 'totp'])
    })

    it('issues a refresh cookie when configured', async () => {
      const t = new JwtTransport({
        ...baseCfg,
        refresh: { cookieName: '__Host-rt', ttlMs: 86_400_000 },
      })
      const intents = t.issue('plain-sid', fakeSession(), { fresh: true, absolute: false })
      const cookieIntent = intents.find((i) => i.type === 'setCookie')
      expect(cookieIntent).toBeDefined()
      if (cookieIntent?.type === 'setCookie') {
        expect(cookieIntent.name).toBe('__Host-rt')
        expect(cookieIntent.value).toBe('plain-sid')
        expect(cookieIntent.options.httpOnly).toBe(true)
      }
    })
  })

  describe('extract', () => {
    it('parses Authorization: Bearer header', () => {
      const t = new JwtTransport(baseCfg)
      const h = new Headers({ authorization: 'Bearer token.value.sig' })
      expect(t.extract({ headers: h })).toBe('token.value.sig')
    })

    it('returns null for missing or malformed Authorization header', () => {
      const t = new JwtTransport(baseCfg)
      expect(t.extract({ headers: new Headers() })).toBeNull()
      expect(t.extract({ headers: new Headers({ authorization: 'Basic xxx' }) })).toBeNull()
    })
  })

  describe('verify failure paths', () => {
    it('returns null for a malformed JWT', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify('not.a.jwt')).toBeNull()
      expect(await t.verify('only-one-part')).toBeNull()
    })

    it('returns null for a tampered signature', async () => {
      const t = new JwtTransport(baseCfg)
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = (intents.find((i) => i.type === 'json') as { body: { access_token: string } }).body.access_token
      const tampered = `${token.slice(0, -3)}xxx`
      expect(await t.verify(tampered)).toBeNull()
    })

    it('returns null for an unknown kid', async () => {
      const t = new JwtTransport(baseCfg)
      // Re-encode header to set a kid the transport doesn't know.
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = (intents.find((i) => i.type === 'json') as { body: { access_token: string } }).body.access_token
      const [, payload, sig] = token.split('.')
      const fakeHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'unknown' })).toString('base64url')
      expect(await t.verify(`${fakeHeader}.${payload}.${sig}`)).toBeNull()
    })

    it('returns null for an expired JWT', async () => {
      const t = new JwtTransport({ ...baseCfg, ttlMs: -1 })
      const intents = t.issue('sid', fakeSession({ expiresAt: Date.now() + 60_000 }), {
        fresh: true,
        absolute: false,
      })
      const token = (intents.find((i) => i.type === 'json') as { body: { access_token: string } }).body.access_token
      expect(await t.verify(token)).toBeNull()
    })

    it('returns null when alg is wrong', async () => {
      const t = new JwtTransport(baseCfg)
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = (intents.find((i) => i.type === 'json') as { body: { access_token: string } }).body.access_token
      const [, payload, sig] = token.split('.')
      const wrongHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: 'k1' })).toString('base64url')
      expect(await t.verify(`${wrongHeader}.${payload}.${sig}`)).toBeNull()
    })

    it('returns null when issuer does not match', async () => {
      const t1 = new JwtTransport(baseCfg)
      const t2 = new JwtTransport({ ...baseCfg, issuer: 'https://different.example.com' })
      const token = (
        t1.issue('sid', fakeSession(), { fresh: true, absolute: false }).find((i) => i.type === 'json') as {
          body: { access_token: string }
        }
      ).body.access_token
      expect(await t2.verify(token)).toBeNull()
    })
  })

  describe('key rotation', () => {
    it('verifies a token issued by an older key still in verifyKeys', async () => {
      const t1 = new JwtTransport({
        signKey: { kid: 'old', key: 'old-secret' },
        verifyKeys: [{ kid: 'old', key: 'old-secret' }],
        issuer: 'https://app',
      })
      const intents = t1.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = (intents.find((i) => i.type === 'json') as { body: { access_token: string } }).body.access_token

      // After rotation: sign with new key but keep old in verifyKeys for overlap.
      const t2 = new JwtTransport({
        signKey: { kid: 'new', key: 'new-secret' },
        verifyKeys: [
          { kid: 'new', key: 'new-secret' },
          { kid: 'old', key: 'old-secret' },
        ],
        issuer: 'https://app',
      })
      expect(await t2.verify(token)).not.toBeNull()
    })

    it('rejects a token signed with a verify-key whose notAfter has passed', async () => {
      const t = new JwtTransport({
        signKey: { kid: 'k1', key: 'k1-secret' },
        verifyKeys: [{ kid: 'k1', key: 'k1-secret', notAfter: Date.now() - 1 }],
        issuer: 'https://app',
      })
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = (intents.find((i) => i.type === 'json') as { body: { access_token: string } }).body.access_token
      expect(await t.verify(token)).toBeNull()
    })
  })

  describe('revoke', () => {
    it('returns clearCookie intent when refresh enabled', () => {
      const t = new JwtTransport({ ...baseCfg, refresh: { cookieName: '__Host-rt' } })
      const intents = t.revoke()
      expect(intents.some((i) => i.type === 'clearCookie' && i.name === '__Host-rt')).toBe(true)
    })

    it('returns json intent only when refresh disabled', () => {
      const t = new JwtTransport(baseCfg)
      const intents = t.revoke()
      expect(intents.some((i) => i.type === 'json')).toBe(true)
      expect(intents.some((i) => i.type === 'clearCookie')).toBe(false)
    })
  })
})
