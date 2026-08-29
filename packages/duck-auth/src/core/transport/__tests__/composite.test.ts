/**
 * The composite transport is the only place in the library where one request
 * can present more than one credential, and where one token can be judged by
 * more than one verifier. Both are resolved by position in an array: first
 * non-empty extraction wins, first successful verification wins.
 *
 * That makes the array order a security decision, and this file is the first
 * test coverage the class has. The cases ask what happens when the transports
 * disagree, which is the situation composing them creates.
 *
 * Sources: RFC 6750 section 2 on presenting a bearer token by exactly one
 * method, RFC 9449 on what a DPoP-bound token is worth if an unbound path
 * remains, and OWASP ASVS V3 on session-token handling.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Provider } from '~/core/provider/provider.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { makeSession } from '~/test/store-inputs'
import { BearerTransport } from '../bearer.transport'
import { CompositeTransport, compositeTransport } from '../composite.transport'
import { CookieTransport } from '../cookie.transport'
import type { Transport } from '../transport.types'

const SESSION = makeSession({ id: 'sid-hashed', identityId: 'u1' })
const OPTS: Transport.IssueOpts = { absolute: false, fresh: true }

/** A transport whose every answer is chosen by the case. */
function stub(name: string, over: Partial<Transport.ITransport> = {}): Transport.ITransport {
  return {
    extract: () => null,
    issue: () => [{ body: { from: name }, status: 200, type: 'json' }],
    revoke: () => [{ body: { revoked: name }, status: 200, type: 'json' }],
    ...over,
  }
}

const req = (headers: Record<string, string>) => ({ headers: new Headers(headers) })

describe('construction', () => {
  it('refuses an empty transport list', () => {
    expect(() => new CompositeTransport([])).toThrow(/at least one transport/)
  })

  it('the factory builds the same thing', () => {
    expect(compositeTransport([stub('a')])).toBeInstanceOf(CompositeTransport)
  })

  it('FINDING: it throws a bare Error rather than the library’s misconfiguration code', () => {
    // Every other wiring mistake in this library raises AUTH_MISCONFIGURED with a
    // detail and a status. A server adapter's error handler recognises that and
    // not this, so an empty list surfaces as an unhandled five hundred.
    const err = (() => {
      try {
        new CompositeTransport([])
      } catch (e) {
        return e as { code?: string }
      }
    })()
    expect(err?.code).toBeUndefined()
  })

  it('FINDING: the same transport can be listed twice, and everything it emits is doubled', () => {
    // Nothing deduplicates. A config assembled from two partial lists issues two
    // identical cookies and two identical bodies.
    const one = stub('a')
    expect(new CompositeTransport([one, one]).issue('sid', SESSION, OPTS)).toHaveLength(2)
  })
})

describe('extract resolves a request carrying two credentials by array order', () => {
  const cookie = new CookieTransport({ name: 'duck-sid', secure: true })
  const bearer = new BearerTransport()

  it('falls through to the next transport when the first finds nothing', () => {
    const composite = new CompositeTransport([cookie, bearer])
    expect(composite.extract(req({ authorization: 'Bearer token-from-header' }))).toBe('token-from-header')
  })

  it('uses the first transport when only it matches', () => {
    const composite = new CompositeTransport([cookie, bearer])
    expect(composite.extract(req({ cookie: 'duck-sid=token-from-cookie' }))).toBe('token-from-cookie')
  })

  it('returns null when no transport matches', () => {
    expect(new CompositeTransport([cookie, bearer]).extract(req({}))).toBeNull()
  })

  it('FINDING: a request presenting two different credentials is silently resolved, not refused', () => {
    // RFC 6750 section 2 says a client must not send a token by more than one
    // method, and that a request doing so must be rejected. Here the array order
    // picks a winner and the other credential is discarded without a word. An
    // attacker who can plant a cookie, which a sibling subdomain can do, chooses
    // which identity the request runs as whenever cookie is listed first.
    const cookieFirst = new CompositeTransport([cookie, bearer])
    const bearerFirst = new CompositeTransport([bearer, cookie])
    const both = req({ authorization: 'Bearer honest-token', cookie: 'duck-sid=planted-token' })

    expect(cookieFirst.extract(both)).toBe('planted-token')
    expect(bearerFirst.extract(both)).toBe('honest-token')
  })

  it('FINDING: reordering the array changes which credential authenticates the request', () => {
    // The order is the whole policy, and nothing in the type or the constructor
    // signals that. Two deployments with the same transports in different orders
    // resolve the same request to different sessions.
    const a = stub('a', { extract: () => 'from-a' })
    const b = stub('b', { extract: () => 'from-b' })
    expect(new CompositeTransport([a, b]).extract(req({}))).toBe('from-a')
    expect(new CompositeTransport([b, a]).extract(req({}))).toBe('from-b')
  })

  it('FINDING: a transport that throws on extract takes the whole chain with it', () => {
    // The loop has no guard, so one adapter raising on a malformed header stops
    // the later transports from ever being asked, and the request fails rather
    // than falling back to the credential it also carried.
    const boom = stub('boom', {
      extract: () => {
        throw new Error('malformed cookie header')
      },
    })
    const healthy = stub('healthy', { extract: () => 'usable-token' })
    expect(() => new CompositeTransport([boom, healthy]).extract(req({}))).toThrow('malformed cookie header')
  })

  it('treats an empty string from a transport as no match and keeps looking', () => {
    const blank = stub('blank', { extract: () => '' })
    const real = stub('real', { extract: () => 'found' })
    expect(new CompositeTransport([blank, real]).extract(req({}))).toBe('found')
  })
})

describe('verify accepts a token any one transport will vouch for', () => {
  const verifying = (name: string, answer: Sessions.Me | null): Transport.ITransport =>
    stub(name, { verify: async () => answer })

  it('returns the first successful verification', async () => {
    const composite = new CompositeTransport([verifying('a', null), verifying('b', SESSION)])
    expect(await composite.verify('token')).toBe(SESSION)
  })

  it('returns null when nothing verifies', async () => {
    expect(await new CompositeTransport([verifying('a', null)]).verify('token')).toBeNull()
  })

  it('skips a transport that has no verify at all', async () => {
    const composite = new CompositeTransport([new BearerTransport(), verifying('b', SESSION)])
    expect(await composite.verify('token')).toBe(SESSION)
  })

  it('refuses a token that is empty, oversize or not a string before asking anyone', async () => {
    const asked = vi.fn(async () => SESSION)
    const composite = new CompositeTransport([stub('a', { verify: asked })])

    for (const token of ['', 'x'.repeat(4097), 42 as never, null as never]) {
      expect(await composite.verify(token)).toBeNull()
    }
    expect(asked).not.toHaveBeenCalled()
  })

  it('accepts a token sitting exactly on the cap', async () => {
    const composite = new CompositeTransport([stub('a', { verify: async () => SESSION })])
    expect(await composite.verify('x'.repeat(4096))).toBe(SESSION)
  })

  it('FINDING: composing a strict transport with a lenient one yields the lenient one', () => {
    // This is the important one. Verification is a disjunction: a token only has
    // to satisfy one member of the array. Adding a proof-of-possession transport
    // such as DPoP alongside a plain bearer or JWT transport therefore adds no
    // security at all, because the unbound path is still there and answers
    // first-come. The strict transport's refusal is not a veto, it is a pass.
    const strict = stub('dpop', { verify: async () => null }) // no proof supplied
    const lenient = stub('jwt', { verify: async () => SESSION })

    return expect(new CompositeTransport([strict, lenient]).verify('unbound-token')).resolves.toBe(SESSION)
  })

  it('FINDING: a transport that throws during verify blocks the ones after it', async () => {
    // A JWKS fetch failure or a decode crash in one transport prevents the rest
    // from being tried, so a recoverable fault in the optional transport takes
    // down the primary one.
    const broken = stub('broken', {
      verify: async () => {
        throw new Error('jwks unreachable')
      },
    })
    const working = stub('working', { verify: async () => SESSION })
    await expect(new CompositeTransport([broken, working]).verify('token')).rejects.toThrow('jwks unreachable')
  })

  it('FINDING: verification is sequential, so its latency is the sum of every miss', async () => {
    const order: string[] = []
    const slow = (name: string, answer: Sessions.Me | null) =>
      stub(name, {
        verify: async () => {
          order.push(`start-${name}`)
          await new Promise((r) => setTimeout(r, 5))
          order.push(`end-${name}`)
          return answer
        },
      })
    await new CompositeTransport([slow('a', null), slow('b', null), slow('c', SESSION)]).verify('token')
    expect(order).toEqual(['start-a', 'end-a', 'start-b', 'end-b', 'start-c', 'end-c'])
  })

  it('FINDING: the shared cap is hard-coded rather than asked of the transports', () => {
    // The comment says 4096 "is the largest any shipped transport accepts". It is
    // a constant in the composite, so a custom transport with a larger ceiling
    // silently cannot be reached through a composite, and a shipped one whose
    // ceiling is later raised is silently clamped here.
    const composite = new CompositeTransport([stub('a', { verify: async () => SESSION })])
    return expect(composite.verify('x'.repeat(5000))).resolves.toBeNull()
  })
})

describe('issue and revoke fan out to every transport', () => {
  it('emits the intents of all of them, in order', () => {
    const composite = new CompositeTransport([stub('a'), stub('b')])
    expect(composite.issue('sid', SESSION, OPTS)).toEqual([
      { body: { from: 'a' }, status: 200, type: 'json' },
      { body: { from: 'b' }, status: 200, type: 'json' },
    ])
  })

  it('passes the same sid, session and options to each', () => {
    const seen: Array<{ opts: Transport.IssueOpts; sid: string }> = []
    const spy = (name: string) =>
      stub(name, {
        issue: (sid, _session, opts) => {
          seen.push({ opts, sid })
          return []
        },
      })
    new CompositeTransport([spy('a'), spy('b')]).issue('the-sid', SESSION, { ...OPTS, csrfToken: 'csrf' })
    expect(seen).toHaveLength(2)
    expect(seen[0]).toEqual(seen[1])
    expect(seen[0]?.opts.csrfToken).toBe('csrf')
  })

  it('FINDING: composing two body-emitting transports produces two json intents for one response', () => {
    // A response has one body. Bearer and JWT both answer `issue` with a json
    // intent, so composing them hands the server adapter two, and which one the
    // client receives is decided by whatever the adapter does with a list it was
    // never told could contain duplicates. One of the two tokens is lost.
    const composite = new CompositeTransport([new BearerTransport(), new BearerTransport({ header: 'x-token' })])
    const intents = composite.issue('sid', SESSION, OPTS)
    expect(intents.filter((i) => i.type === 'json')).toHaveLength(2)
  })

  it('FINDING: revoke has the same shape, so a sign-out emits several conflicting bodies', () => {
    const composite = new CompositeTransport([new BearerTransport(), new BearerTransport()])
    expect(composite.revoke().filter((i) => i.type === 'json')).toHaveLength(2)
  })

  it('a cookie and a bearer compose cleanly, which is the documented case', () => {
    const composite = new CompositeTransport([
      new CookieTransport({ name: 'duck-sid', secure: true }),
      new BearerTransport(),
    ])
    const intents = composite.issue('sid', SESSION, OPTS)
    expect(intents.filter((i) => i.type === 'setCookie')).toHaveLength(1)
    expect(intents.filter((i) => i.type === 'json')).toHaveLength(1)
  })

  it('FINDING: issue is not transactional, so a throwing transport loses the intents already built', () => {
    // `flatMap` has no guard. If the third transport raises, the cookie the first
    // one produced never reaches the response, and the session row it was issued
    // for has already been written by the caller.
    const boom = stub('boom', {
      issue: () => {
        throw new Error('cannot sign')
      },
    })
    const composite = new CompositeTransport([stub('a'), boom])
    expect(() => composite.issue('sid', SESSION, OPTS)).toThrow('cannot sign')
  })

  it('FINDING: revoke drops a transport whose revocation is server-side without saying so', () => {
    // Bearer's own revoke is a note that the client should forget the token; the
    // real revocation is the store delete the caller must perform. Composing it
    // in makes the response look like a complete sign-out.
    const composite = new CompositeTransport([new BearerTransport()])
    expect(composite.revoke()).toEqual([{ body: { revoked: true }, status: 200, type: 'json' }])
  })
})

describe('the bearer transport it is usually composed with', () => {
  const bearer = new BearerTransport()

  it('matches the scheme case-insensitively and trims the token', () => {
    expect(bearer.extract(req({ authorization: 'bearer   tok  ' }))).toBe('tok')
    expect(bearer.extract(req({ authorization: 'BEARER tok' }))).toBe('tok')
  })

  it('refuses another scheme, an empty token, and an oversize one', () => {
    expect(bearer.extract(req({ authorization: 'Basic dXNlcjpwYXNz' }))).toBeNull()
    expect(bearer.extract(req({ authorization: 'Bearer ' }))).toBeNull()
    expect(bearer.extract(req({ authorization: `Bearer ${'x'.repeat(4097)}` }))).toBeNull()
  })

  it('refuses a token carrying a comma, which is how two headers arrive joined', () => {
    expect(bearer.extract(req({ authorization: 'Bearer a, Bearer b' }))).toBeNull()
  })

  it('FINDING: an empty scheme silently disables the transport instead of being refused', () => {
    // The prefix becomes a single space, and `Headers` strips leading whitespace
    // from a value, so nothing can ever match it. Nothing validates the scheme at
    // construction, so a config that blanks it produces a transport that extracts
    // nothing, forever, with no error. In a composite that reads as "this
    // credential was not presented".
    const loose = new BearerTransport({ scheme: '' })
    expect(loose.extract(req({ authorization: 'anything-at-all' }))).toBeNull()
    expect(loose.extract(req({ authorization: ' leading-space' }))).toBeNull()
  })

  it('handles a multi-word scheme, since the prefix is matched whole', () => {
    const spaced = new BearerTransport({ scheme: 'DPoP Bearer' })
    expect(spaced.extract(req({ authorization: 'dpop bearer tok' }))).toBe('tok')
    expect(spaced.extract(req({ authorization: 'Bearer tok' }))).toBeNull()
  })

  it('FINDING: the issued body carries the plaintext session id, so any body logger records it', () => {
    // Documented, and unavoidable for a bearer flow, but worth pinning next to
    // the composite: this is the value that authenticates the client, and it is
    // in a response body rather than a cookie the browser hides.
    expect(bearer.issue('plaintext-sid', SESSION)).toEqual([
      { body: { expiresAt: SESSION.expiresAt, token: 'plaintext-sid' }, status: 200, type: 'json' },
    ])
  })

  it('has no verify, so a composite always falls through past it', () => {
    expect((bearer as Transport.ITransport).verify).toBeUndefined()
  })
})
