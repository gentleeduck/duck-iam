/**
 * The OAuth `state` parameter is this client's CSRF defence, its PKCE verifier
 * carrier, and its mix-up defence, all in one HMAC-signed string that makes a
 * round trip through an authorization server the client does not control.
 */
import { Buffer } from 'node:buffer'
import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { sha256 } from '~/core/crypto'
import { authBuildState, authVerifyState, signState } from '../state'

const SECRET = 'state-signing-secret-value'
const OTHER_SECRET = 'a-completely-different-secret'
/** The pair `begin` splits: the cookie stays in the browser, its digest rides in the state. */
const COOKIE = 'pre-auth-cookie-value'
const BINDING = sha256(COOKIE)

const build = (over: Record<string, unknown> = {}) => ({
  ...authBuildState('oauth:authGoogle', 'pkce-verifier-value', { binding: BINDING }),
  ...over,
})

/** Re-sign an arbitrary payload, the way the library would. */
const sign = (payload: unknown, secret = SECRET) => signState(payload as never, secret)

/** Forge the `body.sig` shape directly, for cases signState will not produce. */
function forge(bodyJson: string, secret = SECRET): string {
  const body = Buffer.from(bodyJson, 'utf8').toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

describe('a state the library signed comes back intact', () => {
  it('round-trips the payload', () => {
    const payload = build()
    const verified = authVerifyState(sign(payload), SECRET)
    expect(verified).toMatchObject({
      nonce: payload.nonce,
      providerId: 'oauth:authGoogle',
      verifier: 'pkce-verifier-value',
    })
  })

  it('carries returnTo when one was set', () => {
    const payload = authBuildState('oauth:authGoogle', 'v', { binding: BINDING, returnTo: '/dashboard' })
    expect(authVerifyState(sign(payload), SECRET)?.returnTo).toBe('/dashboard')
  })

  it('omits returnTo when none was set, rather than inventing an empty one', () => {
    expect(authVerifyState(sign(build()), SECRET)).not.toHaveProperty('returnTo')
  })

  it('mints a fresh nonce every time', () => {
    const nonces = new Set<string>()
    for (let i = 0; i < 1000; i++) nonces.add(authBuildState('p', 'v', { binding: BINDING }).nonce)
    expect(nonces.size).toBe(1000)
  })

  it('survives unicode in returnTo', () => {
    const returnTo = '/dashboard/naïve/🦆'
    expect(authVerifyState(sign(authBuildState('p', 'v', { binding: BINDING, returnTo })), SECRET)?.returnTo).toBe(
      returnTo,
    )
  })
})

describe('anything the library did not sign is refused', () => {
  it('refuses a body altered after signing', () => {
    const [body, sig] = sign(build()).split('.')
    const tampered = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(body as string, 'base64url').toString()), providerId: 'evil' }),
    ).toString('base64url')
    expect(authVerifyState(`${tampered}.${sig}`, SECRET)).toBeNull()
  })

  it('refuses a signature altered after signing', () => {
    const [body, sig] = sign(build()).split('.')
    const flipped = `${(sig as string).slice(0, -1)}${(sig as string).endsWith('A') ? 'B' : 'A'}`
    expect(authVerifyState(`${body}.${flipped}`, SECRET)).toBeNull()
  })

  it('refuses a state signed with a different secret', () => {
    // The whole point: an authorization server, or anyone who saw a state, cannot
    // mint one the client will accept.
    expect(authVerifyState(sign(build(), OTHER_SECRET), SECRET)).toBeNull()
  })

  it('refuses when verified against the wrong secret', () => {
    expect(authVerifyState(sign(build()), OTHER_SECRET)).toBeNull()
  })

  it('refuses a signature lifted from a different state', () => {
    const [bodyA] = sign(build()).split('.')
    const [, sigB] = sign(build({ nonce: 'different' })).split('.')
    expect(authVerifyState(`${bodyA}.${sigB}`, SECRET)).toBeNull()
  })

  it('refuses an empty signature', () => {
    const [body] = sign(build()).split('.')
    expect(authVerifyState(`${body}.`, SECRET)).toBeNull()
  })

  it('refuses a signature of the wrong length without throwing', () => {
    // node's timingSafeEqual throws on length mismatch; the length guard ahead of
    // it is what turns that into a refusal rather than a 500.
    const [body] = sign(build()).split('.')
    for (const sig of ['a', 'ab'.repeat(100), '']) {
      expect(() => authVerifyState(`${body}.${sig}`, SECRET)).not.toThrow()
      expect(authVerifyState(`${body}.${sig}`, SECRET)).toBeNull()
    }
  })
})

describe('shapes that are not a state at all', () => {
  for (const [label, value] of [
    ['empty string', ''],
    ['no separator', 'justonepart'],
    ['three parts, JWT-shaped', 'a.b.c'],
    ['four parts', 'a.b.c.d'],
    ['only a separator', '.'],
    ['leading separator', '.sig'],
    ['whitespace', '   '],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(authVerifyState(value, SECRET)).toBeNull()
    })
  }

  for (const [label, value] of [
    ['undefined', undefined],
    ['null', null],
    ['a number', 12345],
    ['an object', { body: 'a', sig: 'b' }],
    ['an array', ['a', 'b']],
    ['a boolean', true],
  ] as const) {
    it(`refuses ${label} without throwing`, () => {
      expect(() => authVerifyState(value as never, SECRET)).not.toThrow()
      expect(authVerifyState(value as never, SECRET)).toBeNull()
    })
  }

  it('refuses an oversize state before parsing it', () => {
    // The 8KB cap is what stops a multi-megabyte base64 body becoming a parse DoS.
    const huge = `${'a'.repeat(9000)}.${'b'.repeat(43)}`
    expect(authVerifyState(huge, SECRET)).toBeNull()
  })

  it('accepts a state just under the cap', () => {
    const returnTo = '/x'.repeat(500)
    expect(authVerifyState(sign(authBuildState('p', 'v', { binding: BINDING, returnTo })), SECRET)?.returnTo).toBe(
      returnTo,
    )
  })
})

describe('a correctly signed body that is not a valid payload', () => {
  // Each of these is signed with the real secret, so only the payload validation
  // stands between them and acceptance.
  for (const [label, json] of [
    ['a JSON array', '[]'],
    ['a JSON string', '"hello"'],
    ['a JSON number', '42'],
    ['JSON null', 'null'],
    ['an empty object', '{}'],
    ['not JSON at all', 'definitely-not-json'],
  ] as const) {
    it(`refuses ${label}`, () => {
      expect(authVerifyState(forge(json), SECRET)).toBeNull()
    })
  }

  /** Every other field present and well-formed, so each row below is refused for the field it names. */
  const wholePayload = { binding: BINDING, iat: Date.now(), nonce: 'n', providerId: 'p', verifier: 'v' }

  for (const [label, over] of [
    ['a missing nonce', { nonce: undefined }],
    ['an empty nonce', { nonce: '' }],
    ['a non-string nonce', { nonce: 42 }],
    ['a missing verifier', { verifier: undefined }],
    ['an empty verifier', { verifier: '' }],
    ['a missing providerId', { providerId: undefined }],
    ['an empty providerId', { providerId: '' }],
    ['a missing binding', { binding: undefined }],
    ['an empty binding', { binding: '' }],
    ['a non-string binding', { binding: 42 }],
    ['a missing iat', { iat: undefined }],
    ['a string iat', { iat: '123' }],
    ['a NaN iat', { iat: Number.NaN }],
    ['an infinite iat', { iat: Number.POSITIVE_INFINITY }],
    ['a non-string returnTo', { returnTo: 42 }],
    ['a returnTo past the two-kilobyte cap', { returnTo: 'x'.repeat(2049) }],
  ] as const) {
    it(`refuses ${label}`, () => {
      // JSON.stringify drops an undefined value, which is how a row names a missing field.
      expect(authVerifyState(forge(JSON.stringify({ ...wholePayload, ...over })), SECRET)).toBeNull()
    })
  }

  it('takes that payload with nothing overridden, so each refusal above is the field it names', () => {
    expect(authVerifyState(forge(JSON.stringify(wholePayload)), SECRET)).not.toBeNull()
  })

  it('ignores extra fields rather than carrying them through', () => {
    // A payload the client did not put there must not survive into the verified
    // object, or a signed state becomes a way to smuggle data into the callback.
    const payload = { ...build(), evil: 'smuggled', identityId: 'admin' }
    const verified = authVerifyState(sign(payload), SECRET)
    expect(verified).not.toHaveProperty('evil')
    expect(verified).not.toHaveProperty('identityId')
  })
})

describe('age', () => {
  it('refuses a state older than the default ten minutes', () => {
    const payload = build({ iat: Date.now() - 11 * 60 * 1000 })
    expect(authVerifyState(sign(payload), SECRET)).toBeNull()
  })

  it('accepts a state just inside the window', () => {
    const payload = build({ iat: Date.now() - 9 * 60 * 1000 })
    expect(authVerifyState(sign(payload), SECRET)).not.toBeNull()
  })

  it('honours a caller-supplied window', () => {
    const payload = build({ iat: Date.now() - 5000 })
    expect(authVerifyState(sign(payload), SECRET, { maxAgeMs: 1000 })).toBeNull()
    expect(authVerifyState(sign(payload), SECRET, { maxAgeMs: 60_000 })).not.toBeNull()
  })

  it('refuses a state stamped far enough in the future to outlive its window', () => {
    // `now - iat > maxAge` alone reads a future stamp as a negative age and passes it forever, so a
    // clock that jumps backwards makes every state minted before the jump immortal.
    const payload = build({ iat: Date.now() + 365 * 24 * 60 * 60 * 1000 })
    expect(authVerifyState(sign(payload), SECRET)).toBeNull()
  })

  it('still allows the small forward skew a two-machine deployment produces', () => {
    const payload = build({ iat: Date.now() + 1000 })
    expect(authVerifyState(sign(payload), SECRET, { maxAgeMs: 60_000 })).not.toBeNull()
  })
})

describe('binding to one provider, which is the mix-up defence', () => {
  it('reports the provider the state was minted for', () => {
    // The callback compares this against its own id and refuses a mismatch, so a
    // state issued for one authorization server cannot be replayed at another.
    expect(
      authVerifyState(sign(authBuildState('oauth:authGoogle', 'v', { binding: BINDING })), SECRET)?.providerId,
    ).toBe('oauth:authGoogle')
    expect(
      authVerifyState(sign(authBuildState('oauth:authGithub', 'v', { binding: BINDING })), SECRET)?.providerId,
    ).toBe('oauth:authGithub')
  })

  it('a state cannot be re-pointed at another provider without breaking the signature', () => {
    const [body, sig] = sign(authBuildState('oauth:authGoogle', 'v', { binding: BINDING })).split('.')
    const decoded = JSON.parse(Buffer.from(body as string, 'base64url').toString()) as Record<string, unknown>
    const repointed = Buffer.from(JSON.stringify({ ...decoded, providerId: 'oauth:authGithub' })).toString('base64url')
    expect(authVerifyState(`${repointed}.${sig}`, SECRET)).toBeNull()
  })
})

describe('the state is stateless, so it verifies as many times as it is presented', () => {
  it('the same state verifies repeatedly inside its window', () => {
    // Pinned as a property rather than fixed: single use needs a server-side record of what is
    // outstanding, and this helper is handed a secret and a string. The authorization code it
    // accompanies is single-use at the authorization server, which is what stops a second use
    // going anywhere.
    const state = sign(build())
    for (let i = 0; i < 5; i++) expect(authVerifyState(state, SECRET)).not.toBeNull()
  })
})

describe('the verifier it carries', () => {
  it('comes back byte for byte, since PKCE fails on any drift', () => {
    const verifier = 'A'.repeat(43)
    expect(authVerifyState(sign(authBuildState('p', verifier, { binding: BINDING })), SECRET)?.verifier).toBe(verifier)
  })

  it('survives a verifier containing base64url punctuation', () => {
    const verifier = 'abc-_123.~'
    expect(authVerifyState(sign(authBuildState('p', verifier, { binding: BINDING })), SECRET)?.verifier).toBe(verifier)
  })
})
