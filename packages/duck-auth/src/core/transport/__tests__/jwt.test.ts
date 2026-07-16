import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Sessions } from '~/core/sessions/sessions.types'
import { JwtTransport } from '../jwt.transport'

/**
 * SEC helper: mint an HS256-signed JWT with caller-supplied (and
 * possibly malformed) header / payload objects. Used to exercise the
 * runtime claim validators that defend against missing/non-typed claims.
 * Signature is correct so the verifier reaches the claim-parsing path.
 */
function mintHs256(headerObj: unknown, payloadObj: unknown, secret: string): string {
  const headerB64 = Buffer.from(JSON.stringify(headerObj)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const sig = createHmac('sha256', secret).update(signingInput).digest('base64url')
  return `${signingInput}.${sig}`
}

function fakeSession(overrides: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = Date.now()
  return {
    id: 'row-hash',
    identityId: 'user-1',
    kind: 'user',
    aal: 2,
    factors: [
      { method: 'password', completedAt: new Date(now) },
      { method: 'totp', completedAt: new Date(now) },
    ],
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
    ...overrides,
  }
}

describe('AuthJwtTransport', () => {
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

    it('accepts case-variant scheme (RFC 7235 §2.1 case-insensitive)', () => {
      const t = new JwtTransport(baseCfg)
      expect(t.extract({ headers: new Headers({ authorization: 'bearer abc.def.sig' }) })).toBe('abc.def.sig')
      expect(t.extract({ headers: new Headers({ authorization: 'BEARER abc.def.sig' }) })).toBe('abc.def.sig')
    })

    it('rejects an oversize token (DoS via large Authorization header)', () => {
      const t = new JwtTransport(baseCfg)
      const huge = 'x'.repeat(4097)
      expect(t.extract({ headers: new Headers({ authorization: `Bearer ${huge}` }) })).toBeNull()
    })

    it('rejects a token containing comma (multi-Authorization-header smuggling defense)', () => {
      const t = new JwtTransport(baseCfg)
      const headers = new Headers()
      headers.append('authorization', 'Bearer aaa.bbb.ccc')
      headers.append('authorization', 'Bearer ddd.eee.fff')
      expect(t.extract({ headers })).toBeNull()
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
      const intents = t.issue('sid', fakeSession({ expiresAt: new Date(Date.now() + 60_000) }), {
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

  describe('verify failure paths - SEC: claim validation', () => {
    const header = { alg: 'HS256', typ: 'JWT', kid: 'k1' }
    const secret = 'super-secret-key-for-tests-only'
    const validPayload = {
      iss: 'https://app.example.com',
      sub: 'user-1',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      sid: 'row-hash',
      aal: 2,
      factors: ['password'],
    }

    it('rejects a token whose exp is missing (would bypass expiry via NaN math)', async () => {
      const t = new JwtTransport(baseCfg)
      const { exp, ...payloadNoExp } = validPayload
      void exp
      expect(await t.verify(mintHs256(header, payloadNoExp, secret))).toBeNull()
    })

    it('rejects a token whose exp is a string', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(header, { ...validPayload, exp: '9999999999' }, secret))).toBeNull()
    })

    it('rejects a token whose iat is missing', async () => {
      const t = new JwtTransport(baseCfg)
      const { iat, ...payloadNoIat } = validPayload
      void iat
      expect(await t.verify(mintHs256(header, payloadNoIat, secret))).toBeNull()
    })

    it('rejects a token whose factors is not an array (would crash with TypeError .map)', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(header, { ...validPayload, factors: 'password' }, secret))).toBeNull()
    })

    it('rejects a token whose factors contains an unknown method (would slip past as-cast)', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(header, { ...validPayload, factors: ['evil-method'] }, secret))).toBeNull()
    })

    it('rejects a token whose aal is not 1/2/3 (would skew AAL gating)', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(header, { ...validPayload, aal: 99 }, secret))).toBeNull()
    })

    it('rejects a token whose payload is a JSON array (not an object)', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(header, ['not', 'an', 'object'], secret))).toBeNull()
    })

    it('rejects a token whose header is a JSON array (not an object)', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(['not', 'an', 'object'], validPayload, secret))).toBeNull()
    })

    it('rejects a token whose acting_as is a non-object (would land malformed envelope on session)', async () => {
      const t = new JwtTransport(baseCfg)
      expect(await t.verify(mintHs256(header, { ...validPayload, acting_as: 'not-an-object' }, secret))).toBeNull()
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

  describe('constructor validation', () => {
    it('throws AUTH/MISCONFIGURED on duplicate kid in verifyKeys', () => {
      try {
        new JwtTransport({
          signKey: { kid: 'k1', key: 'a-secret' },
          verifyKeys: [
            { kid: 'k1', key: 'a-secret' },
            { kid: 'k1', key: 'a-DIFFERENT-secret' },
          ],
          issuer: 'https://app',
        })
        throw new Error('expected throw')
      } catch (err) {
        expect((err as { code: string }).code).toBe('AUTH_MISCONFIGURED')
        expect((err as { meta: { detail: string } }).meta.detail).toMatch(/duplicate kid/)
      }
    })

    it('throws AUTH/MISCONFIGURED when signKey HS256 mismatches a verifyKey under the same kid', () => {
      try {
        new JwtTransport({
          signKey: { kid: 'k1', key: 'sign-secret' },
          verifyKeys: [{ kid: 'k1', key: 'a-DIFFERENT-verify-secret' }],
          issuer: 'https://app',
        })
        throw new Error('expected throw')
      } catch (err) {
        expect((err as { code: string }).code).toBe('AUTH_MISCONFIGURED')
        expect((err as { meta: { detail: string } }).meta.detail).toMatch(/does not match/)
      }
    })

    it('throws AUTH/MISCONFIGURED when signKey alg mismatches a verifyKey under the same kid', () => {
      try {
        new JwtTransport({
          signKey: { kid: 'k1', alg: 'HS256', key: 'same-secret' },
          verifyKeys: [{ kid: 'k1', alg: 'ES256', key: 'same-secret' }],
          issuer: 'https://app',
        })
        throw new Error('expected throw')
      } catch (err) {
        expect((err as { code: string }).code).toBe('AUTH_MISCONFIGURED')
        expect((err as { meta: { detail: string } }).meta.detail).toMatch(/alg/)
      }
    })
  })

  describe('fresh-flag from frsh claim (not hard-coded)', () => {
    it('verify reconstructs fresh=true when rotatedAt is within freshnessMs', async () => {
      const t = new JwtTransport({ ...baseCfg, freshnessMs: 5 * 60_000 })
      const session = fakeSession({ rotatedAt: new Date(Date.now()) })
      const token = (
        t.issue('sid', session, { fresh: true, absolute: false }).find((i) => i.type === 'json') as {
          body: { access_token: string }
        }
      ).body.access_token
      const back = await t.verify(token)
      expect(back?.fresh).toBe(true)
    })

    it('verify reconstructs fresh=false when rotatedAt is older than freshnessMs', async () => {
      const t = new JwtTransport({ ...baseCfg, freshnessMs: 1_000 })
      // Mint a JWT with a rotatedAt 10s in the past.
      const session = fakeSession({ rotatedAt: new Date(Date.now() - 10_000) })
      const token = (
        t.issue('sid', session, { fresh: true, absolute: false }).find((i) => i.type === 'json') as {
          body: { access_token: string }
        }
      ).body.access_token
      const back = await t.verify(token)
      expect(back?.fresh).toBe(false)
    })

    it('rotatedAt round-trips via the `frsh` claim, not iat', async () => {
      const t = new JwtTransport(baseCfg)
      const rotatedAtMs = Date.now() - 2_000
      const session = fakeSession({ rotatedAt: new Date(rotatedAtMs) })
      const token = (
        t.issue('sid', session, { fresh: true, absolute: false }).find((i) => i.type === 'json') as {
          body: { access_token: string }
        }
      ).body.access_token
      const back = await t.verify(token)
      // Within 1s of the original rotatedAt (we floor to seconds on the wire).
      expect(Math.abs((back?.rotatedAt?.getTime() ?? 0) - rotatedAtMs)).toBeLessThan(1_000)
    })
  })
})
