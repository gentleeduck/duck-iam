import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { answer } from '~/core/answer'
import { InMemoryEvents } from '~/core/events'
import { HijackFacet } from '~/core/hijack'
import { isRecord } from '~/core/predicates'
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

function accessToken(intents: ReturnType<JwtTransport['issue']>): string {
  const body = intents.find((i) => i.type === 'json')?.body
  if (!isRecord(body) || typeof body.access_token !== 'string') throw new Error('no access token issued')
  return body.access_token
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
    updatedAt: new Date(now),
    rotatedAt: new Date(now),
    expiresAt: new Date(now + 60_000),
    absoluteExpiresAt: new Date(now + 60_000),
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
      const token = accessToken(intents)
      expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)

      const back = await t.verify(token)
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
      await expect(t.verify('not.a.jwt')).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
      await expect(t.verify('only-one-part')).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
    })

    it('returns null for a tampered signature', async () => {
      const t = new JwtTransport(baseCfg)
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = accessToken(intents)
      const tampered = `${token.slice(0, -3)}xxx`
      await expect(t.verify(tampered)).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
    })

    it('returns null for an unknown kid', async () => {
      const t = new JwtTransport(baseCfg)
      // Re-encode header to set a kid the transport doesn't know.
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = accessToken(intents)
      const [, payload, sig] = token.split('.')
      const fakeHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'unknown' })).toString('base64url')
      await expect(t.verify(`${fakeHeader}.${payload}.${sig}`)).rejects.toMatchObject({ code: 'AUTH_JWT_KEY_UNKNOWN' })
    })

    it('returns null for an expired JWT', async () => {
      const t = new JwtTransport(baseCfg)
      // `exp` is bounded by the session's own deadline, so a session that has already ended mints a dead token.
      const intents = t.issue('sid', fakeSession({ expiresAt: new Date(Date.now() - 10_000) }), {
        fresh: true,
        absolute: false,
      })
      const token = accessToken(intents)
      await expect(t.verify(token)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
    })

    it('returns null when alg is wrong', async () => {
      const t = new JwtTransport(baseCfg)
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = accessToken(intents)
      const [, payload, sig] = token.split('.')
      const wrongHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: 'k1' })).toString('base64url')
      await expect(t.verify(`${wrongHeader}.${payload}.${sig}`)).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
    })

    it('returns null when issuer does not match', async () => {
      const t1 = new JwtTransport(baseCfg)
      const t2 = new JwtTransport({ ...baseCfg, issuer: 'https://different.example.com' })
      const token = accessToken(t1.issue('sid', fakeSession(), { fresh: true, absolute: false }))
      await expect(t2.verify(token)).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
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
      await expect(t.verify(mintHs256(header, payloadNoExp, secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })

    it('rejects a token whose exp is a string', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(t.verify(mintHs256(header, { ...validPayload, exp: '9999999999' }, secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })

    it('rejects a token whose iat is missing', async () => {
      const t = new JwtTransport(baseCfg)
      const { iat, ...payloadNoIat } = validPayload
      void iat
      await expect(t.verify(mintHs256(header, payloadNoIat, secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })

    it('rejects a token whose factors is not an array (would crash with TypeError .map)', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(t.verify(mintHs256(header, { ...validPayload, factors: 'password' }, secret))).rejects.toMatchObject(
        { code: 'AUTH_JWT_INVALID' },
      )
    })

    it('rejects a token whose factors contains an unknown method (would slip past as-cast)', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(
        t.verify(mintHs256(header, { ...validPayload, factors: ['evil-method'] }, secret)),
      ).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
    })

    it('rejects a token whose aal is not 1/2/3 (would skew AAL gating)', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(t.verify(mintHs256(header, { ...validPayload, aal: 99 }, secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })

    it('rejects a token whose payload is a JSON array (not an object)', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(t.verify(mintHs256(header, ['not', 'an', 'object'], secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })

    it('rejects a token whose header is a JSON array (not an object)', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(t.verify(mintHs256(['not', 'an', 'object'], validPayload, secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })

    it('rejects a token whose acting_as is a non-object (would land malformed envelope on session)', async () => {
      const t = new JwtTransport(baseCfg)
      await expect(
        t.verify(mintHs256(header, { ...validPayload, acting_as: 'not-an-object' }, secret)),
      ).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
    })

    it.each([
      ['ip', { ip: 7 }],
      ['ua', { ua: ['curl'] }],
    ])('rejects a token whose %s is not a string', async (_, claim) => {
      const t = new JwtTransport(baseCfg)
      await expect(t.verify(mintHs256(header, { ...validPayload, ...claim }, secret))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })
  })

  describe('the hijack baseline', () => {
    const ip = '203.0.113.10'
    const userAgent = 'Mozilla/5.0 (Macintosh) Safari/605'

    it('carries the address and user agent the session recorded, and none it did not', async () => {
      const t = new JwtTransport(baseCfg)
      const bound = await t.verify(
        accessToken(t.issue('sid', fakeSession({ ip, userAgent }), { fresh: true, absolute: false })),
      )
      expect({ ip: bound.ip, userAgent: bound.userAgent }).toEqual({ ip, userAgent })
      const bare = await t.verify(accessToken(t.issue('sid', fakeSession(), { fresh: true, absolute: false })))
      expect({ ip: bare.ip, userAgent: bare.userAgent }).toEqual({ ip: null, userAgent: null })
    })

    it('lets the hijack policy refuse a drift, and pass the request the session was bound to', async () => {
      const t = new JwtTransport(baseCfg)
      const session = await t.verify(
        accessToken(t.issue('sid', fakeSession({ ip, userAgent }), { fresh: true, absolute: false })),
      )
      const hijack = new HijackFacet(
        new InMemoryEvents(),
        { revokeByHash: () => answer(async () => session) },
        { onIpChange: 'revoke' },
      )
      expect(await hijack.evaluate(session, { ip: '198.51.100.7', userAgent })).toMatchObject({ reaction: 'revoke' })
      expect(await hijack.evaluate(session, { ip, userAgent })).toEqual({ ok: true })
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
      const token = accessToken(intents)

      // After rotation: sign with new key but keep old in verifyKeys for overlap.
      const t2 = new JwtTransport({
        signKey: { kid: 'new', key: 'new-secret' },
        verifyKeys: [
          { kid: 'new', key: 'new-secret' },
          { kid: 'old', key: 'old-secret' },
        ],
        issuer: 'https://app',
      })
      await expect(t2.verify(token)).resolves.toBeDefined()
    })

    it('rejects a token signed with a verify-key whose notAfter has passed', async () => {
      const t = new JwtTransport({
        signKey: { kid: 'k1', key: 'k1-secret' },
        verifyKeys: [{ kid: 'k1', key: 'k1-secret', notAfter: Date.now() - 1 }],
        issuer: 'https://app',
      })
      const intents = t.issue('sid', fakeSession(), { fresh: true, absolute: false })
      const token = accessToken(intents)
      await expect(t.verify(token)).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
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
    const misconfigured = (detail: RegExp) =>
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: expect.objectContaining({ detail: expect.stringMatching(detail) }),
      })

    it('throws AUTH_MISCONFIGURED on duplicate kid in verifyKeys', () => {
      expect(
        () =>
          new JwtTransport({
            signKey: { kid: 'k1', key: 'a-secret' },
            verifyKeys: [
              { kid: 'k1', key: 'a-secret' },
              { kid: 'k1', key: 'a-DIFFERENT-secret' },
            ],
            issuer: 'https://app',
          }),
      ).toThrow(misconfigured(/duplicate kid/))
    })

    it('throws AUTH_MISCONFIGURED when signKey HS256 mismatches a verifyKey under the same kid', () => {
      expect(
        () =>
          new JwtTransport({
            signKey: { kid: 'k1', key: 'sign-secret' },
            verifyKeys: [{ kid: 'k1', key: 'a-DIFFERENT-verify-secret' }],
            issuer: 'https://app',
          }),
      ).toThrow(misconfigured(/does not match/))
    })

    it('throws AUTH_MISCONFIGURED when signKey alg mismatches a verifyKey under the same kid', () => {
      expect(
        () =>
          new JwtTransport({
            signKey: { kid: 'k1', alg: 'HS256', key: 'same-secret' },
            verifyKeys: [{ kid: 'k1', alg: 'ES256', key: 'same-secret' }],
            issuer: 'https://app',
          }),
      ).toThrow(misconfigured(/alg/))
    })

    it('refuses a time window that is not a finite positive number, which a variable left unset makes NaN', () => {
      const cases: Array<Partial<JwtTransport.Cfg>> = [
        { clockSkewSec: Number.NaN },
        { clockSkewSec: -1 },
        { ttlMs: Number.NaN },
        { ttlMs: 0 },
        { freshnessMs: Number.NaN },
        { refresh: { ttlMs: Number.NaN } },
      ]
      for (const cfg of cases) {
        expect(() => new JwtTransport({ ...baseCfg, ...cfg }), JSON.stringify(Object.keys(cfg))).toThrow(
          misconfigured(/clockSkewSec|ttlMs|freshnessMs/),
        )
      }
    })

    it('mints with the windows it was given', () => {
      const t = new JwtTransport({ ...baseCfg, refresh: { ttlMs: 86_400_000 } })
      const later = new Date(Date.now() + 3_600_000)
      const intents = t.issue('plain-sid', fakeSession({ absoluteExpiresAt: later, expiresAt: later }), {
        absolute: false,
        fresh: true,
      })
      expect(intents).toContainEqual(
        expect.objectContaining({ body: expect.objectContaining({ expires_in: 60 }), type: 'json' }),
      )
      expect(intents).toContainEqual(
        expect.objectContaining({ options: expect.objectContaining({ maxAge: 86_400 }), type: 'setCookie' }),
      )
    })
  })

  describe('the absolute ceiling', () => {
    it('a session whose ceiling nothing can read mints a token nothing accepts, as the facet reads it expired', async () => {
      const t = new JwtTransport(baseCfg)
      const issue = (s: Sessions.Me): string => accessToken(t.issue('sid', s, { absolute: false, fresh: true }))
      await expect(t.verify(issue(fakeSession()))).resolves.toMatchObject({ identityId: 'user-1' })
      await expect(t.verify(issue(fakeSession({ absoluteExpiresAt: new Date(Number.NaN) })))).rejects.toMatchObject({
        code: 'AUTH_JWT_INVALID',
      })
    })
  })

  describe('fresh-flag from frsh claim (not hard-coded)', () => {
    it('verify reconstructs fresh=true when rotatedAt is within freshnessMs', async () => {
      const t = new JwtTransport({ ...baseCfg, freshnessMs: 5 * 60_000 })
      const session = fakeSession({ rotatedAt: new Date(Date.now()) })
      const token = accessToken(t.issue('sid', session, { fresh: true, absolute: false }))
      const back = await t.verify(token)
      expect(back?.fresh).toBe(true)
    })

    it('verify reconstructs fresh=false when rotatedAt is older than freshnessMs', async () => {
      const t = new JwtTransport({ ...baseCfg, freshnessMs: 1_000 })
      // Mint a JWT with a rotatedAt 10s in the past.
      const session = fakeSession({ rotatedAt: new Date(Date.now() - 10_000) })
      const token = accessToken(t.issue('sid', session, { fresh: true, absolute: false }))
      const back = await t.verify(token)
      expect(back?.fresh).toBe(false)
    })

    it('rotatedAt round-trips via the `frsh` claim, not iat', async () => {
      const t = new JwtTransport(baseCfg)
      const rotatedAtMs = Date.now() - 2_000
      const session = fakeSession({ rotatedAt: new Date(rotatedAtMs) })
      const token = accessToken(t.issue('sid', session, { fresh: true, absolute: false }))
      const back = await t.verify(token)
      // Within 1s of the original rotatedAt (we floor to seconds on the wire).
      expect(Math.abs((back?.rotatedAt?.getTime() ?? 0) - rotatedAtMs)).toBeLessThan(1_000)
    })
  })
  describe('verify answers a verdict', () => {
    it('rejects a token it does not vouch for, and orNull reads that back as null', async () => {
      const t = new JwtTransport(baseCfg)
      for (const bad of ['not.a.jwt', 'a.b', 'a.b.c.d', '']) {
        await expect(t.verify(bad)).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
        await expect(t.verify(bad).orNull()).resolves.toBeNull()
      }
    })

    it('rejects a token signed by a key it does not hold', async () => {
      const t = new JwtTransport(baseCfg)
      const forged = mintHs256({ alg: 'HS256', kid: 'k1' }, { sub: 'user-1' }, 'not-the-signing-key')
      await expect(t.verify(forged)).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
    })
  })
})
