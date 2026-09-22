/**
 * The composite transport is the only place in the library where one request
 * can present more than one credential, and where one token can be judged by
 * more than one verifier. Both are resolved by position in an array: first
 * non-empty extraction wins, first successful verification wins.
 */
import { describe, expect, it, vi } from 'vitest'
import { AuthError } from '~/core/errors'
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
    issue: () => [{ name: `sid-${name}`, options: {}, type: 'setCookie', value: name }],
    revoke: () => [{ name: `sid-${name}`, options: {}, type: 'clearCookie' }],
    ...over,
  }
}

const req = (headers: Record<string, string>) => ({ headers: new Headers(headers) })

describe('construction', () => {
  it('refuses an empty transport list', () => {
    expect(() => new CompositeTransport([])).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: '@gentleduck/auth AuthCompositeTransport: at least one transport required' },
      }),
    )
  })

  it('the factory builds the same thing', () => {
    expect(compositeTransport([stub('a')])).toBeInstanceOf(CompositeTransport)
  })

  it('lists one transport once however many times it was passed', () => {
    // A config assembled from two partial lists issued two identical cookies and two identical
    // bodies for the same transport.
    const one = stub('a')
    expect(new CompositeTransport([one, one]).issue('sid', SESSION, OPTS)).toHaveLength(1)
    // Two distinct instances stay two: they are the documented cookie-plus-bearer case.
    expect(new CompositeTransport([stub('a'), stub('b')]).issue('sid', SESSION, OPTS)).toHaveLength(2)
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

  it('refuses a request presenting two different credentials rather than picking one', () => {
    // RFC 6750 section 2 says a client must not send a token by more than one method and that a
    // request doing so must be rejected. Array order used to pick a winner and discard the other
    // without a word, so anyone who can plant a cookie - a sibling subdomain can - chose which
    // identity the request ran as whenever cookie was listed first.
    const both = req({ authorization: 'Bearer honest-token', cookie: 'duck-sid=planted-token' })
    for (const order of [
      [cookie, bearer],
      [bearer, cookie],
    ]) {
      expect(() => new CompositeTransport(order).extract(both)).toThrow(
        expect.objectContaining({ code: 'AUTH_INVALID_CREDENTIALS' }),
      )
    }
  })

  it('the same token arriving by two methods is one credential, not two', () => {
    const same = req({ authorization: 'Bearer tok', cookie: 'duck-sid=tok' })
    expect(new CompositeTransport([cookie, bearer]).extract(same)).toBe('tok')
  })

  it('a deployment mid-migration can opt back into first-wins', () => {
    // Refusing is the default because it is what the RFC says; this exists because a deployment
    // moving from cookie to bearer legitimately sends both for a while.
    const both = req({ authorization: 'Bearer honest-token', cookie: 'duck-sid=planted-token' })
    const lenient = new CompositeTransport([cookie, bearer], { onMultipleCredentials: 'first' })
    expect(lenient.extract(both)).toBe('planted-token')
  })

  it('order no longer decides which of two credentials wins, because two are refused', () => {
    // Order remains the tiebreak for `verify`, where a token may satisfy more than one transport.
    // It is no longer the tiebreak for which credential a request is judged by.
    const a = stub('a', { extract: () => 'from-a' })
    const b = stub('b', { extract: () => 'from-b' })
    expect(() => new CompositeTransport([a, b]).extract(req({}))).toThrow(
      expect.objectContaining({ code: 'AUTH_INVALID_CREDENTIALS' }),
    )
    expect(() => new CompositeTransport([b, a]).extract(req({}))).toThrow(
      expect.objectContaining({ code: 'AUTH_INVALID_CREDENTIALS' }),
    )
  })

  it('keeps asking the later transports when one throws on a header it cannot parse', () => {
    const boom = stub('boom', {
      extract: () => {
        throw new Error('malformed cookie header')
      },
    })
    const healthy = stub('healthy', { extract: () => 'usable-token' })
    expect(new CompositeTransport([boom, healthy]).extract(req({}))).toBe('usable-token')
  })

  it('raises the parse failure when nothing else produced a credential', () => {
    // Swallowing it into a bare `null` would turn a malformed header into a plain "not signed in",
    // which is the one answer that hides the reason.
    const boom = stub('boom', {
      extract: () => {
        throw new Error('malformed cookie header')
      },
    })
    const empty = stub('empty', { extract: () => null })
    expect(() => new CompositeTransport([boom, empty]).extract(req({}))).toThrow('malformed cookie header')
  })

  it('treats an empty string from a transport as no match and keeps looking', () => {
    const blank = stub('blank', { extract: () => '' })
    const real = stub('real', { extract: () => 'found' })
    expect(new CompositeTransport([blank, real]).extract(req({}))).toBe('found')
  })
})

describe('verify accepts a token any one transport will vouch for', () => {
  const verifying = (name: string, answer: Sessions.Me | null): Transport.ITransport =>
    stub(name, {
      verify: async () => {
        if (!answer) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `${name} does not vouch` })

        return answer
      },
    })

  it('returns the first successful verification', async () => {
    const composite = new CompositeTransport([verifying('a', null), verifying('b', SESSION)])
    expect(await composite.verify('token')).toBe(SESSION)
  })

  it('rejects when nothing verifies', async () => {
    await expect(new CompositeTransport([verifying('a', null)]).verify('token')).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
  })

  it('skips a transport that has no verify at all', async () => {
    const composite = new CompositeTransport([new BearerTransport(), verifying('b', SESSION)])
    expect(await composite.verify('token')).toBe(SESSION)
  })

  it('refuses a token that is empty, oversize or not a string before asking anyone', async () => {
    const asked = vi.fn(async () => SESSION)
    const composite = new CompositeTransport([stub('a', { verify: asked })])

    for (const token of ['', 'x'.repeat(4097), 42 as never, null as never]) {
      await expect(composite.verify(token)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    }
    expect(asked).not.toHaveBeenCalled()
  })

  it('accepts a token sitting exactly on the cap', async () => {
    const composite = new CompositeTransport([stub('a', { verify: async () => SESSION })])
    expect(await composite.verify('x'.repeat(4096))).toBe(SESSION)
  })

  it('a strict transport can veto rather than be fallen through past', async () => {
    // The important one. Verification is a disjunction - a token only has to satisfy one member -
    // so a proof-of-possession transport such as DPoP next to a plain bearer added no security at
    // all: the unbound path was still there and answered for the tokens the bound one rejected.
    const declines = { reason: 'no proof supplied' }
    const strict = stub('dpop', {
      authoritative: true,
      verify: () => Promise.reject(new AuthError('AUTH_SESSION_REVOKED', declines)),
    })
    const lenient = stub('jwt', { verify: async () => SESSION })
    await expect(new CompositeTransport([strict, lenient]).verify('unbound-token')).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })

    // Without it the disjunction stands, which is what composing two equally-trusted transports is.
    const optional = stub('dpop', { verify: () => Promise.reject(new AuthError('AUTH_SESSION_REVOKED', declines)) })
    expect(await new CompositeTransport([optional, lenient]).verify('unbound-token')).toBe(SESSION)
  })

  it('an authoritative transport that does vouch still answers', async () => {
    const strict = stub('dpop', { authoritative: true, verify: async () => SESSION })
    expect(await new CompositeTransport([strict, stub('jwt')]).verify('bound-token')).toBe(SESSION)
  })

  it('keeps asking the later transports when one throws during verify', async () => {
    // A JWKS fetch failure or a decode crash in one transport stopped the rest being tried, so a
    // recoverable fault in an optional transport took down the primary one.
    const broken = stub('broken', {
      verify: async () => {
        throw new Error('jwks unreachable')
      },
    })
    const working = stub('working', { verify: async () => SESSION })
    expect(await new CompositeTransport([broken, working]).verify('token')).toBe(SESSION)
  })

  it('raises the verify failure when nothing else vouched for the token', async () => {
    // Same reasoning as extract: swallowing it into `null` turns an unreachable JWKS into a plain
    // "not signed in", which is the one answer that hides the reason.
    const broken = stub('broken', {
      verify: async () => {
        throw new Error('jwks unreachable')
      },
    })
    await expect(
      new CompositeTransport([
        broken,
        stub('quiet', {
          verify: () => Promise.reject(new AuthError('AUTH_SESSION_REVOKED', { reason: 'quiet declines' })),
        }),
      ]).verify('t'),
    ).rejects.toThrow('jwks unreachable')
  })

  it('verifies sequentially, which is what makes order the tiebreak', async () => {
    // Left as it is. Asking every transport at once would decide a token two of them would vouch
    // for by whichever resolved first, and the cost is bounded by the number of transports.
    const order: string[] = []
    const slow = (name: string, answer: Sessions.Me | null) =>
      stub(name, {
        verify: async () => {
          order.push(`start-${name}`)
          await new Promise((r) => setTimeout(r, 5))
          order.push(`end-${name}`)
          if (!answer) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `${name} does not vouch` })

          return answer
        },
      })
    await new CompositeTransport([slow('a', null), slow('b', null), slow('c', SESSION)]).verify('token')
    expect(order).toEqual(['start-a', 'end-a', 'start-b', 'end-b', 'start-c', 'end-c'])
  })

  it('takes its cap from the transports rather than carrying its own constant', async () => {
    // 4096 was hard-coded with a comment saying it was "the largest any shipped transport accepts",
    // so a custom transport with a wider ceiling could not be reached through a composite at all,
    // and a shipped one whose ceiling was later raised was silently clamped back.
    const narrow = new CompositeTransport([stub('a', { verify: async () => SESSION })])
    await expect(narrow.verify('x'.repeat(5000))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })

    const wide = new CompositeTransport([stub('a', { maxTokenLength: 16_384, verify: async () => SESSION })])
    expect(await wide.verify('x'.repeat(5000))).toBe(SESSION)
    await expect(wide.verify('x'.repeat(16_385))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })

    // The widest member sets it, since a token only has to reach the transport that will vouch.
    const mixed = new CompositeTransport([stub('a'), stub('b', { maxTokenLength: 8192, verify: async () => SESSION })])
    expect(mixed.maxTokenLength).toBe(8192)
  })
})

describe('issue and revoke fan out to every transport', () => {
  it('emits the intents of all of them, in order', () => {
    const composite = new CompositeTransport([stub('a'), stub('b')])
    expect(composite.issue('sid', SESSION, OPTS)).toEqual([
      { name: 'sid-a', options: {}, type: 'setCookie', value: 'a' },
      { name: 'sid-b', options: {}, type: 'setCookie', value: 'b' },
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

  it('refuses to compose two body-emitting transports, rather than losing one of the tokens', () => {
    // A response has one body. Bearer and JWT both answer `issue` with a json intent, so composing
    // them handed the server adapter two and which one the client received was decided by whatever
    // the adapter did with a list it was never told could hold duplicates.
    const composite = new CompositeTransport([new BearerTransport(), new BearerTransport({ header: 'x-token' })])
    expect(() => composite.issue('sid', SESSION, OPTS)).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('revoke has the same shape and the same refusal', () => {
    const composite = new CompositeTransport([new BearerTransport(), new BearerTransport({ header: 'x-token' })])
    expect(() => composite.revoke()).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
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

  it('emits nothing at all when one transport throws mid-issue', () => {
    // Left as it is, and deliberate: half a sign-in on the wire is worse than none. The caller has
    // already written the session row by this point, so it is the caller's job to undo it - which
    // it can only do if the throw reaches it, which is why nothing is swallowed here.
    const boom = stub('boom', {
      issue: () => {
        throw new Error('cannot sign')
      },
    })
    const composite = new CompositeTransport([stub('a'), boom])
    expect(() => composite.issue('sid', SESSION, OPTS)).toThrow('cannot sign')
  })

  it('bearer revoke is a note to the client, not the revocation itself', () => {
    // Pinned rather than changed: bearer has nothing server-side to revoke, so its intent asks the
    // client to forget the token and the real revocation is the store delete the caller performs.
    // A composite cannot make that any more complete than the transport it is composing.
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

  it('refuses a scheme that could never match instead of extracting nothing forever', () => {
    for (const scheme of ['', '   ', ' Bearer', 'Bearer ']) {
      expect(() => new BearerTransport({ scheme })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
    expect(() => new BearerTransport({ header: '  ' })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    expect(() => new BearerTransport({ scheme: 'DPoP Bearer' })).not.toThrow()
  })

  it('handles a multi-word scheme, since the prefix is matched whole', () => {
    const spaced = new BearerTransport({ scheme: 'DPoP Bearer' })
    expect(spaced.extract(req({ authorization: 'dpop bearer tok' }))).toBe('tok')
    expect(spaced.extract(req({ authorization: 'Bearer tok' }))).toBeNull()
  })

  it('the issued body carries the plaintext session id, which is what a bearer flow is', () => {
    // Pinned rather than changed: the client has to receive the value that authenticates it, and a
    // bearer flow has no cookie to hide it in. Worth stating next to the composite because it is in
    // a response body, so anything logging bodies records a live credential.
    expect(bearer.issue('plaintext-sid', SESSION)).toEqual([
      { body: { expiresAt: SESSION.expiresAt, token: 'plaintext-sid' }, status: 200, type: 'json' },
    ])
  })

  it('has no verify, so a composite always falls through past it', () => {
    expect((bearer as Transport.ITransport).verify).toBeUndefined()
  })
})

describe('verify tells a negative verdict from a broken transport', () => {
  it('asks the next transport when one is broken, and surfaces the fault when none vouch', async () => {
    const boom = stub('boom', { verify: () => Promise.reject(new Error('jwks unreachable')) })
    const vouches = stub('ok', { verify: async () => SESSION })
    // A JWKS failure in one transport must not take down the transports after it.
    await expect(new CompositeTransport([boom, vouches]).verify('tok')).resolves.toMatchObject({
      id: SESSION.id,
    })
    // With nobody left to vouch, the fault surfaces rather than a bare "no session".
    await expect(new CompositeTransport([boom]).verify('tok')).rejects.toThrow('jwks unreachable')
  })

  it('rejects AUTH_SESSION_REVOKED when every transport simply declines', async () => {
    const declines = stub('declines', {
      verify: () => Promise.reject(new AuthError('AUTH_SESSION_REVOKED', { reason: 'not mine' })),
    })
    const composite = new CompositeTransport([declines, declines])

    await expect(composite.verify('tok')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    await expect(composite.verify('tok').orNull()).resolves.toBeNull()
  })

  it('lets an authoritative refusal veto the transports behind it', async () => {
    // SECURITY: without the veto, putting a bound transport in front of a plain bearer adds nothing -
    // the unbound one answers for every token the bound one rejected.
    const strict = stub('strict', {
      authoritative: true,
      verify: () => Promise.reject(new AuthError('AUTH_SESSION_REVOKED', { reason: 'unbound token' })),
    })
    const permissive = stub('permissive', { verify: async () => SESSION })

    await expect(new CompositeTransport([strict, permissive]).verify('tok')).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
    // Order is what makes it a veto: behind the permissive transport it never gets asked.
    await expect(new CompositeTransport([permissive, strict]).verify('tok')).resolves.toMatchObject({
      id: SESSION.id,
    })
  })

  it('surfaces a transport that threw a falsy value rather than calling it "nobody vouched"', async () => {
    // `if (failure)` instead of `if (failure !== undefined)` reports this as a clean negative verdict.
    const falsy = stub('falsy', { verify: () => Promise.reject('') })

    await expect(new CompositeTransport([falsy]).verify('tok')).rejects.toBe('')
  })
})
