import { describe, expect, it } from 'vitest'
import { BearerTransport } from '../bearer'

function authWithStorybook(value: string): { headers: Headers } {
  return { headers: new Headers({ authorization: value }) }
}

describe('AuthBearerTransport.extract', () => {
  const t = new BearerTransport()

  it('returns the token when a well-formed Bearer header is present', () => {
    expect(t.extract(authWithStorybook('Bearer abc123'))).toBe('abc123')
  })

  it('returns null when no authorization header present', () => {
    expect(t.extract({ headers: new Headers() })).toBeNull()
  })

  it('returns null for a scheme mismatch (Basic instead of Bearer)', () => {
    expect(t.extract(authWithStorybook('Basic dXNlcjpwYXNz'))).toBeNull()
  })

  it('returns null for an empty token after the scheme', () => {
    expect(t.extract(authWithStorybook('Bearer   '))).toBeNull()
    expect(t.extract(authWithStorybook('Bearer '))).toBeNull()
  })

  it('trims surrounding whitespace from the token', () => {
    expect(t.extract(authWithStorybook('Bearer   abc123  '))).toBe('abc123')
  })

  describe('hardened scheme matching + multi-header defense', () => {
    it('accepts case variants of the scheme (RFC 7235 §2.1 - case-insensitive)', () => {
      // Previously `bearer` lowercase was rejected; many HTTP libraries
      // emit lowercase schemes.
      expect(t.extract(authWithStorybook('bearer abc123'))).toBe('abc123')
      expect(t.extract(authWithStorybook('BEARER abc123'))).toBe('abc123')
      expect(t.extract(authWithStorybook('BeArEr abc123'))).toBe('abc123')
    })

    it('rejects a token containing comma (multi-Authorization-header smuggling defense)', () => {
      // Two Authorization headers join with `, ` (Fetch spec); reject defensively.
      const headers = new Headers()
      headers.append('authorization', 'Bearer sid-A')
      headers.append('authorization', 'Bearer sid-B')
      expect(t.extract({ headers })).toBeNull()
    })

    it('rejects a token whose own value contains a comma (defensive - opaque SIDs/JWTs do not have commas)', () => {
      expect(t.extract(authWithStorybook('Bearer abc,def'))).toBeNull()
    })

    it('still rejects a different scheme even with case variants', () => {
      expect(t.extract(authWithStorybook('basic dXNlcjpwYXNz'))).toBeNull()
      expect(t.extract(authWithStorybook('BASIC dXNlcjpwYXNz'))).toBeNull()
    })

    it('rejects an oversize bearer token (DoS via large Authorization header)', () => {
      // HTTP servers commonly allow 8-32k headers. Without the cap, an
      // attacker can submit a multi-KB token and force a downstream
      // sha256 / JWT parse per request.
      const huge = 'x'.repeat(4097)
      expect(t.extract(authWithStorybook(`Bearer ${huge}`))).toBeNull()
    })

    it('accepts a token at the exact cap (4096 chars - accommodates large JWTs)', () => {
      const atCap = 'x'.repeat(4096)
      expect(t.extract(authWithStorybook(`Bearer ${atCap}`))).toBe(atCap)
    })
  })

  describe('custom scheme/header config', () => {
    it('honors a custom scheme name (Token instead of Bearer)', () => {
      const custom = new BearerTransport({ scheme: 'Token' })
      expect(custom.extract(authWithStorybook('Token xyz'))).toBe('xyz')
      expect(custom.extract(authWithStorybook('Bearer xyz'))).toBeNull()
    })

    it('case-insensitive scheme matching applies to custom schemes too', () => {
      const custom = new BearerTransport({ scheme: 'DPoP' })
      expect(custom.extract(authWithStorybook('dpop xyz'))).toBe('xyz')
      expect(custom.extract(authWithStorybook('DPOP xyz'))).toBe('xyz')
    })

    it('honors a custom header name', () => {
      const custom = new BearerTransport({ header: 'x-api-token' })
      expect(custom.extract({ headers: new Headers({ 'x-api-token': 'Bearer abc' }) })).toBe('abc')
    })
  })
})

describe('AuthBearerTransport.issue', () => {
  const t = new BearerTransport()

  it('emits a json intent with token + expiresAt', () => {
    const expiresAt = Date.now() + 60_000
    // @ts-expect-error: this test only exercises the expiresAt projection - the rest of Session.ISession is irrelevant for AuthBearerTransport.issue.
    const intents = t.issue('sid-1', { expiresAt })
    expect(intents).toHaveLength(1)
    const intent = intents[0]
    if (!intent || intent.type !== 'json') throw new Error('expected json intent')
    expect(intent.status).toBe(200)
    expect(intent.body).toEqual({ token: 'sid-1', expiresAt })
  })
})

describe('AuthBearerTransport.revoke', () => {
  it('emits a json intent acknowledging revocation', () => {
    const intents = new BearerTransport().revoke()
    expect(intents).toHaveLength(1)
    const intent = intents[0]
    if (!intent || intent.type !== 'json') throw new Error('expected json intent')
    expect(intent.body).toEqual({ revoked: true })
  })
})
