/**
 * The webhook deliverer is the one place the library makes an outbound request
 * to an address a consumer chose, which makes it the library's SSRF surface, and
 * it is attached to the event bus, which makes its latency the authentication
 * flow's latency. Both of those are pinned here.
 *
 * The existing suite covers the happy path, retries, and the timestamp-bound
 * signature. These cover the guard's edges (what a hostname can be written as),
 * the retry loop's behaviour on failures that will never succeed, and the
 * coupling between delivery and the bus that emitted the event.
 *
 * Sources: OWASP SSRF prevention cheat sheet (deny-list weaknesses, DNS names
 * that resolve inward), RFC 4193 on unique-local IPv6, RFC 4291 section 2.5.6 on
 * the fe80::/10 link-local range, and RFC 1035 section 3.1 on the trailing-dot
 * fully qualified form.
 */
import { describe, expect, it, vi } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { signWebhookBody, verifyWebhookSignature, WebhookDeliverer } from '../index'

const SECRET = 'shhh'
const URL_OK = 'https://hooks.example.com/duck'

/** A deliverer whose transport is a stub, so nothing leaves the process. */
function makeDeliverer(
  over: Partial<WebhookDeliverer.Cfg> = {},
  respond: (n: number) => Response | Promise<Response> = () => new Response('', { status: 200 }),
) {
  const calls: Array<{ init: RequestInit; url: string }> = []
  let n = 0
  const fetchStub = (async (url: unknown, init: unknown) => {
    calls.push({ init: init as RequestInit, url: String(url) })
    return respond(++n)
  }) as unknown as typeof globalThis.fetch

  return {
    calls,
    deliverer: new WebhookDeliverer({
      backoffMs: 0,
      endpoints: [{ secret: SECRET, url: URL_OK }],
      fetch: fetchStub,
      ...over,
    }),
  }
}

const construct = (url: string, cfg: Partial<WebhookDeliverer.Cfg> = {}) =>
  new WebhookDeliverer({ endpoints: [{ secret: SECRET, url }], fetch: (async () => new Response()) as never, ...cfg })

describe('the ssrf guard is a deny-list over the written form of the host', () => {
  it('refuses the obvious loopback and private forms', () => {
    for (const host of [
      'localhost',
      '127.0.0.1',
      '10.0.0.1',
      '192.168.1.1',
      '172.16.0.1',
      '169.254.169.254',
      '[::1]',
    ]) {
      expect(() => construct(`https://${host}/hook`)).toThrow()
    }
  })

  it('refuses the decimal, octal and hex spellings of loopback', () => {
    // The parser canonicalises these to 127.0.0.1 before the guard sees them,
    // which is what makes the deny-list work here at all.
    for (const host of ['2130706433', '0177.0.0.1', '0x7f.1', '127.000.000.1']) {
      expect(() => construct(`https://${host}/hook`)).toThrow()
    }
  })

  it('refuses the ipv4-mapped, nat64 and 6to4 ipv6 forms that carry an inner address', () => {
    for (const host of ['[::ffff:127.0.0.1]', '[64:ff9b::7f00:1]', '[2002:7f00:1::]']) {
      expect(() => construct(`https://${host}/hook`)).toThrow()
    }
  })

  it('FINDING: a trailing dot turns localhost into an accepted host', () => {
    // `/^localhost$/` is anchored, and `localhost.` is the fully qualified form
    // of the same name. Every resolver treats it as 127.0.0.1, and the parser
    // keeps the dot, so the one host the guard names by name is one keystroke
    // away from passing.
    expect(() => construct('https://localhost./hook')).not.toThrow()
  })

  it('FINDING: unique-local ipv6 passes because the pattern never accounts for the brackets', () => {
    // `URL.hostname` returns an ipv6 literal wrapped in brackets. The loopback
    // and fe80:: patterns allow for that with `\[?`, but the fc00::/7 pair does
    // not, so the entire private ipv6 range is reachable.
    expect(() => construct('https://[fc00::1]/hook')).not.toThrow()
    expect(() => construct('https://[fd12:3456::1]/hook')).not.toThrow()
  })

  it('FINDING: link-local ipv6 outside the exact fe80:: prefix passes', () => {
    // fe80::/10 spans fe80: through febf:. The bracket-aware pattern matches
    // only a literal `fe80::`, so an address in the same range written any other
    // way is accepted.
    expect(() => construct('https://[febf::1]/hook')).not.toThrow()
    expect(() => construct('https://[fe80:1::1]/hook')).not.toThrow()
  })

  it('FINDING: any dns name that resolves inward is accepted, because only the spelling is checked', () => {
    // The guard runs once, at construction, against a string. A name pointing at
    // 127.0.0.1, or one that answers differently on the second lookup, is exactly
    // what the deny-list cannot see.
    expect(() => construct('https://localtest.me/hook')).not.toThrow()
    expect(() => construct('https://internal.corp.example/hook')).not.toThrow()
  })

  it('FINDING: the patterns match a hostname textually, so ordinary domains are refused', () => {
    // `/^127\./` and friends are tested against the whole hostname, not against a
    // parsed address. A perfectly public name beginning with one of those labels
    // is rejected as loopback.
    expect(() => construct('https://10.example.com/hook')).toThrow()
    expect(() => construct('https://0.example.com/hook')).toThrow()
  })

  it('refuses a non-https scheme unless the dev flag is set, and never a non-http one', () => {
    expect(() => construct('http://hooks.example.com/hook')).toThrow()
    expect(() => construct('http://hooks.example.com/hook', { allowInsecure: true })).not.toThrow()
    for (const url of ['ftp://hooks.example.com/', 'file:///etc/passwd', 'javascript:fetch(1)']) {
      expect(() => construct(url, { allowInsecure: true })).toThrow()
    }
  })

  it('still refuses loopback when the insecure flag is set', () => {
    expect(() => construct('http://127.0.0.1/hook', { allowInsecure: true })).toThrow()
  })

  it('FINDING: credentials embedded in the endpoint url are accepted and sent', () => {
    // Nothing strips the userinfo, so a configured endpoint can carry a basic-auth
    // pair that then rides in every outbound request and in the dead-letter record.
    expect(() => construct('https://user:pass@hooks.example.com/hook')).not.toThrow()
  })

  it('refuses an unparseable url', () => {
    expect(() => construct('not a url')).toThrow()
  })

  it('refuses an endpoint list that is empty or missing a secret', () => {
    expect(() => new WebhookDeliverer({ endpoints: [] })).toThrow()
    expect(() => new WebhookDeliverer({ endpoints: [{ secret: '', url: URL_OK }] })).toThrow()
    expect(() => new WebhookDeliverer({ endpoints: [{ secret: SECRET, url: '' }] })).toThrow()
  })

  it('checks every endpoint, not just the first', () => {
    expect(
      () =>
        new WebhookDeliverer({
          endpoints: [
            { secret: SECRET, url: URL_OK },
            { secret: SECRET, url: 'https://127.0.0.1/hook' },
          ],
        }),
    ).toThrow()
  })
})

describe('delivery runs inside the emit, so its latency is the caller’s', () => {
  it('FINDING: a failing endpoint holds the emitting flow open for the whole retry ladder', async () => {
    // `attach` subscribes an async handler and `InMemoryEvents.emit` awaits each
    // handler in turn. Every backoff the deliverer sleeps is time the sign-in
    // that emitted the event is still waiting. With the shipped defaults, five
    // attempts at 500ms backoff plus five 5s timeouts, a dead consumer adds up to
    // half a minute to an authentication.
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer(
      { backoffMs: 20, maxAttempts: 4 },
      () => new Response('', { status: 500 }),
    )
    const off = deliverer.attach(bus)

    const started = Date.now()
    await bus.emit('signup.completed', { identity: makeIdentity({ id: 'u' }) })
    const elapsed = Date.now() - started

    expect(calls).toHaveLength(4)
    // 20 + 40 + 80 slept before the caller is released.
    expect(elapsed).toBeGreaterThanOrEqual(130)
    off()
  })

  it('FINDING: the caller is released only after the dead-letter sink has been written', async () => {
    const bus = new InMemoryEvents()
    let sunk = false
    const { deliverer } = makeDeliverer(
      {
        deadLetter: {
          put: async () => {
            await new Promise((r) => setTimeout(r, 20))
            sunk = true
          },
        },
        maxAttempts: 1,
      },
      () => new Response('', { status: 500 }),
    )
    deliverer.attach(bus)

    await bus.emit('maintenance.on', {})
    expect(sunk).toBe(true)
  })

  it('an unsubscribed deliverer stops receiving events', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer()
    const off = deliverer.attach(bus)
    off()
    await bus.emit('maintenance.off', {})
    expect(calls).toHaveLength(0)
  })

  it('FINDING: attaching the same deliverer twice sends every event twice', async () => {
    // `attach` keeps no record of a previous subscription, so a reload path that
    // re-attaches without calling the returned cleanup silently doubles the load
    // on the consumer and the number of retries the caller waits through.
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer()
    deliverer.attach(bus)
    deliverer.attach(bus)
    await bus.emit('maintenance.off', {})
    expect(calls).toHaveLength(2)
  })

  it('FINDING: a wildcard endpoint does not receive authz.revoked', async () => {
    // `'*'` is materialised from a hand-written array of event names, and
    // `authz.revoked` is absent from it. The name is documented as inbound from
    // the IAM side, but a consumer asking for every event still gets a set that
    // silently differs from the event map.
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer({ endpoints: [{ events: '*', secret: SECRET, url: URL_OK }] })
    deliverer.attach(bus)

    await bus.emit('authz.revoked', { at: Date.now(), identityId: 'u' })
    expect(calls).toHaveLength(0)

    await bus.emit('maintenance.off', {})
    expect(calls).toHaveLength(1)
  })

  it('an endpoint naming a subset receives only that subset', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer({
      endpoints: [{ events: ['maintenance.on'], secret: SECRET, url: URL_OK }],
    })
    deliverer.attach(bus)
    await bus.emit('maintenance.off', {})
    await bus.emit('maintenance.on', {})
    expect(calls).toHaveLength(1)
  })

  it('an endpoint naming an empty event list receives nothing', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer({ endpoints: [{ events: [], secret: SECRET, url: URL_OK }] })
    deliverer.attach(bus)
    await bus.emit('maintenance.on', {})
    expect(calls).toHaveLength(0)
  })
})

describe('the retry loop cannot tell a transient failure from a permanent one', () => {
  it('FINDING: a 400 is retried the full ladder even though it will never succeed', async () => {
    // Only `res.ok` is consulted. A consumer rejecting the body, or a wrong
    // signature header name, produces the same five attempts as a timeout.
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 5 }, () => new Response('', { status: 400 }))
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls).toHaveLength(5)
  })

  it('FINDING: a 410 Gone is retried rather than treated as an unsubscribe', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 3 }, () => new Response('', { status: 410 }))
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls).toHaveLength(3)
  })

  it('FINDING: an oversize payload is retried, even though the size cannot change between attempts', async () => {
    // The 1 MiB check happens inside `_dispatch` and returns false, which the
    // retry loop reads as a failed delivery. Nothing is ever sent, but the caller
    // still waits through every backoff before the entry is dead-lettered.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const entries: unknown[] = []
    const { deliverer, calls } = makeDeliverer({
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      maxAttempts: 3,
    })

    await deliverer.deliverOne('suspicious', {
      meta: { blob: 'x'.repeat(1_100_000) },
      score: 1,
      signal: 'test',
    })

    expect(calls).toHaveLength(0)
    expect(entries).toHaveLength(1)
    expect(spy).toHaveBeenCalledTimes(3)
    spy.mockRestore()
  })

  it('FINDING: the payload cap counts utf-16 code units, not the bytes actually sent', async () => {
    // `body.length` on a string of astral characters is half the byte count the
    // request carries, so a body just under the cap can be two megabytes on the
    // wire.
    const { deliverer, calls } = makeDeliverer()
    const emoji = '🐤'.repeat(300_000) // 600k code units, 1.2 MB of utf-8.
    await deliverer.deliverOne('maintenance.on', { message: emoji })

    expect(calls).toHaveLength(1)
    expect(Buffer.byteLength((calls[0]?.init.body as string) ?? '')).toBeGreaterThan(1_048_576)
  })

  it('stops at the first success and does not keep retrying', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 5 }, (n) =>
      n < 3 ? new Response('', { status: 500 }) : new Response('', { status: 200 }),
    )
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls).toHaveLength(3)
  })

  it('treats a 204 as delivered', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 3 }, () => new Response(null, { status: 204 }))
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls).toHaveLength(1)
  })

  it('a thrown transport error is retried and its message reaches the dead letter', async () => {
    const entries: Array<{ attempts: number; lastError: string }> = []
    const { deliverer } = makeDeliverer(
      {
        deadLetter: {
          put: async (e) => {
            entries.push(e)
          },
        },
        maxAttempts: 2,
      },
      () => {
        throw new Error('econnrefused')
      },
    )
    await deliverer.deliverOne('maintenance.on', {})
    expect(entries[0]).toMatchObject({ attempts: 2, lastError: 'econnrefused' })
  })

  it('a dead-letter sink that throws does not propagate to the caller', async () => {
    const { deliverer } = makeDeliverer(
      {
        deadLetter: {
          put: async () => {
            throw new Error('sink down')
          },
        },
        maxAttempts: 1,
      },
      () => new Response('', { status: 500 }),
    )
    await expect(deliverer.deliverOne('maintenance.on', {})).resolves.toBeUndefined()
  })

  it('FINDING: with no dead-letter sink a permanently failed event is dropped in silence', async () => {
    // No sink, no log, no return value. The delivery simply did not happen.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const { deliverer } = makeDeliverer({ maxAttempts: 1 }, () => new Response('', { status: 500 }))
    await expect(deliverer.deliverOne('maintenance.on', {})).resolves.toBeUndefined()
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })

  it('clamps the attempt count into one through twenty', async () => {
    const zero = makeDeliverer({ maxAttempts: 0 }, () => new Response('', { status: 500 }))
    await zero.deliverer.deliverOne('maintenance.on', {})
    expect(zero.calls).toHaveLength(1)
  })

  it('FINDING: a negative backoff is accepted and retries land back to back', async () => {
    // Only `maxAttempts` is clamped. A negative base makes every computed wait
    // negative, which `setTimeout` floors to zero, so the ladder that exists to
    // spare a struggling consumer hammers it instead.
    const { deliverer, calls } = makeDeliverer(
      { backoffMs: -1000, maxAttempts: 5 },
      () => new Response('', { status: 500 }),
    )
    const started = Date.now()
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls).toHaveLength(5)
    // Four sleeps of the configured magnitude would be four seconds.
    expect(Date.now() - started).toBeLessThan(2_000)
  })

  it('FINDING: a backoff large enough to overflow the timer also retries immediately', async () => {
    // The attempt cap was chosen so `backoffMs * 2 ** (attempt - 1)` stays inside
    // the timer range, but that only holds for the default base. A base past
    // 2^31 overflows on the first retry and `setTimeout` fires it at once, so the
    // longest configured delay behaves as the shortest.
    const { deliverer, calls } = makeDeliverer(
      { backoffMs: 2 ** 32, maxAttempts: 3 },
      () => new Response('', { status: 500 }),
    )
    const started = Date.now()
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls).toHaveLength(3)
    // Honouring the base would have slept for more than a month.
    expect(Date.now() - started).toBeLessThan(2_000)
  })

  it('FINDING: retries carry no jitter, so a fleet retries in lockstep', async () => {
    // Every instance that saw the same failure sleeps exactly the same interval.
    const waits: number[] = []
    let previous = Date.now()
    const { deliverer } = makeDeliverer({ backoffMs: 15, maxAttempts: 4 }, () => {
      const now = Date.now()
      waits.push(now - previous)
      previous = now
      return new Response('', { status: 500 })
    })
    await deliverer.deliverOne('maintenance.on', {})
    expect(waits.slice(1).every((w, i) => w >= 15 * 2 ** i)).toBe(true)
  })

  it('fans out to every eligible endpoint concurrently', async () => {
    const seen: string[] = []
    const deliverer = new WebhookDeliverer({
      backoffMs: 0,
      endpoints: [
        { secret: SECRET, url: 'https://a.example.com/h' },
        { secret: SECRET, url: 'https://b.example.com/h' },
      ],
      fetch: (async (url: unknown) => {
        seen.push(String(url))
        await new Promise((r) => setTimeout(r, 5))
        return new Response('', { status: 200 })
      }) as never,
    })
    await deliverer.deliverOne('maintenance.on', {})
    expect(seen).toHaveLength(2)
  })

  it('one endpoint failing does not stop another from being delivered', async () => {
    const ok: string[] = []
    const deliverer = new WebhookDeliverer({
      backoffMs: 0,
      endpoints: [
        { secret: SECRET, url: 'https://a.example.com/h' },
        { secret: SECRET, url: 'https://b.example.com/h' },
      ],
      fetch: (async (url: unknown) => {
        if (String(url).includes('a.example')) throw new Error('down')
        ok.push(String(url))
        return new Response('', { status: 200 })
      }) as never,
      maxAttempts: 1,
    })
    await deliverer.deliverOne('maintenance.on', {})
    expect(ok).toEqual(['https://b.example.com/h'])
  })
})

describe('what actually goes on the wire', () => {
  it('refuses to follow a redirect, so the guarded host stays the host', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('maintenance.on', {})
    expect(calls[0]?.init.redirect).toBe('error')
  })

  it('sends the signature and the timestamp it was computed over', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('maintenance.on', { message: 'hi' })

    const headers = calls[0]?.init.headers as Record<string, string>
    const body = calls[0]?.init.body as string
    const timestamp = Number(headers['x-duck-timestamp'])
    expect(verifyWebhookSignature(SECRET, body, headers['X-Duck-Signature'] as string, { timestamp })).toBe(true)
  })

  it('the body names the event and carries the payload unchanged', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('session.revoked', { identityId: 'u', sessionId: 's' })
    expect(JSON.parse(calls[0]?.init.body as string)).toMatchObject({
      event: 'session.revoked',
      payload: { identityId: 'u', sessionId: 's' },
    })
  })

  it('FINDING: the payload is forwarded verbatim, including whatever a session object carries', async () => {
    // Nothing redacts before signing. A `session.created` payload holds the
    // session record and the identity, so every field either of them carries is
    // posted to a third party by default.
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('session.created', {
      identity: makeIdentity({ id: 'u' }),
      session: makeSession({ id: 'sid', identityId: 'u' }),
    })
    const body = JSON.parse(calls[0]?.init.body as string)
    expect(body.payload.session).toMatchObject({ id: 'sid' })
    expect(body.payload.identity).toMatchObject({ id: 'u' })
  })

  it('FINDING: a payload that cannot be serialised is retried the whole ladder', async () => {
    // `JSON.stringify` runs inside the try that guards the transport, so a
    // circular payload reads as a failed attempt rather than as a permanent
    // error. Nothing is ever sent, and the caller waits through every backoff
    // before the entry is dead-lettered with a TypeError as its last error.
    const entries: Array<{ attempts: number; lastError: string }> = []
    const { deliverer, calls } = makeDeliverer({
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      maxAttempts: 3,
    })
    const circular: Record<string, unknown> = {}
    circular.self = circular

    await deliverer.deliverOne('maintenance.on', circular as never)
    expect(calls).toHaveLength(0)
    expect(entries[0]).toMatchObject({ attempts: 3 })
    expect(entries[0]?.lastError).toMatch(/circular|convert/i)
  })

  it('FINDING: a bigint in the payload is dead-lettered the same way, with nothing sent', async () => {
    const entries: unknown[] = []
    const { deliverer, calls } = makeDeliverer({
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      maxAttempts: 2,
    })
    await deliverer.deliverOne('maintenance.on', { message: 1n } as never)
    expect(calls).toHaveLength(0)
    expect(entries).toHaveLength(1)
  })

  it('honours a custom signature header name', async () => {
    const { deliverer, calls } = makeDeliverer({
      endpoints: [{ secret: SECRET, signatureHeader: 'X-Custom', url: URL_OK }],
    })
    await deliverer.deliverOne('maintenance.on', {})
    expect((calls[0]?.init.headers as Record<string, string>)['X-Custom']).toMatch(/^authSha256=/)
  })

  it('FINDING: an invalid signature header name fails every attempt and dead-letters the event', async () => {
    // The header name is caller-supplied and reaches `fetch` unvalidated, so a
    // typo containing a space or a colon turns into a thrown request for every
    // event, forever.
    const entries: unknown[] = []
    const deliverer = new WebhookDeliverer({
      backoffMs: 0,
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      endpoints: [{ secret: SECRET, signatureHeader: 'X Bad: Header', url: URL_OK }],
      fetch: globalThis.fetch,
      maxAttempts: 1,
    })
    await deliverer.deliverOne('maintenance.on', {})
    expect(entries).toHaveLength(1)
  })

  it('FINDING: the dead-letter record stores the endpoint url, credentials included', async () => {
    const entries: Array<{ endpointId: string; endpointUrl: string }> = []
    const deliverer = new WebhookDeliverer({
      backoffMs: 0,
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      endpoints: [{ secret: SECRET, url: 'https://user:hunter2@hooks.example.com/h' }],
      fetch: (async () => new Response('', { status: 500 })) as never,
      maxAttempts: 1,
    })
    await deliverer.deliverOne('maintenance.on', {})
    expect(entries[0]?.endpointUrl).toContain('hunter2')
    expect(entries[0]?.endpointId).toContain('hunter2')
  })
})

describe('signature verification', () => {
  const BODY = '{"event":"maintenance.on"}'

  it('round-trips and rejects a tampered body', () => {
    const sig = signWebhookBody(SECRET, BODY)
    expect(verifyWebhookSignature(SECRET, BODY, sig)).toBe(true)
    expect(verifyWebhookSignature(SECRET, `${BODY} `, sig)).toBe(false)
  })

  it('rejects the right signature under the wrong secret', () => {
    expect(verifyWebhookSignature('other', BODY, signWebhookBody(SECRET, BODY))).toBe(false)
  })

  it('FINDING: the prefix is authSha256=, not the sha256= the doc comment promises', () => {
    // The comment says the format matches "the convention most webhook tooling
    // uses". It does not, so a consumer written against that sentence, or against
    // a GitHub or Stripe style verifier, rejects every delivery.
    expect(signWebhookBody(SECRET, BODY).startsWith('authSha256=')).toBe(true)
    expect(signWebhookBody(SECRET, BODY).startsWith('sha256=')).toBe(false)
  })

  it('a signature made with a timestamp does not verify without one, and the reverse', () => {
    const withTs = signWebhookBody(SECRET, BODY, 1_700_000_000_000)
    expect(verifyWebhookSignature(SECRET, BODY, withTs)).toBe(false)
    expect(verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY), { timestamp: Date.now() })).toBe(false)
  })

  it('rejects a timestamp outside the tolerance in either direction', () => {
    const old = Date.now() - 6 * 60_000
    const future = Date.now() + 6 * 60_000
    expect(verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY, old), { timestamp: old })).toBe(false)
    expect(verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY, future), { timestamp: future })).toBe(
      false,
    )
  })

  it('accepts a timestamp inside the tolerance', () => {
    const ts = Date.now() - 60_000
    expect(verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY, ts), { timestamp: ts })).toBe(true)
  })

  it('rejects a non-finite or non-numeric timestamp rather than skipping the window', () => {
    for (const timestamp of [Number.NaN, Number.POSITIVE_INFINITY, '123' as never, null as never]) {
      expect(verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY, 1), { timestamp })).toBe(false)
    }
  })

  it('honours a zero tolerance rather than reading it as absent', () => {
    // `??` falls back only on null or undefined, so an operator asking for no
    // slack at all gets none.
    const ts = Date.now() - 60_000
    expect(
      verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY, ts), { timestamp: ts, toleranceMs: 0 }),
    ).toBe(false)
  })

  it('FINDING: a negative tolerance rejects every signature, including a fresh one', () => {
    // Nothing validates the window, and `Math.abs(...) > negative` is true for
    // any gap at all, so a sign error in a consumer's config silently refuses
    // every delivery it receives.
    const ts = Date.now()
    expect(
      verifyWebhookSignature(SECRET, BODY, signWebhookBody(SECRET, BODY, ts), { timestamp: ts, toleranceMs: -1 }),
    ).toBe(false)
  })

  it('FINDING: nothing binds a delivery to a single use inside the window', () => {
    // The timestamp bounds replay but does not prevent it: the same body and
    // signature verify as many times as they are presented for five minutes.
    const ts = Date.now()
    const sig = signWebhookBody(SECRET, BODY, ts)
    for (let i = 0; i < 3; i++) expect(verifyWebhookSignature(SECRET, BODY, sig, { timestamp: ts })).toBe(true)
  })

  it('FINDING: the freshness window is checked against the caller-supplied timestamp, not the signed one', () => {
    // The helper takes the timestamp as an argument and signs with it, so a
    // consumer that reads the value out of the body rather than the header is
    // trusting a number the sender controls. Only the header form is bound.
    const ts = Date.now() - 6 * 60_000
    const sig = signWebhookBody(SECRET, BODY, ts)
    expect(verifyWebhookSignature(SECRET, BODY, sig, { timestamp: ts })).toBe(false)
    expect(verifyWebhookSignature(SECRET, BODY, sig)).toBe(false)
  })

  it('rejects a signature of a different length without comparing it', () => {
    expect(verifyWebhookSignature(SECRET, BODY, 'authSha256=short')).toBe(false)
    expect(verifyWebhookSignature(SECRET, BODY, '')).toBe(false)
  })

  it('rejects a signature that differs only in case', () => {
    const sig = signWebhookBody(SECRET, BODY)
    expect(verifyWebhookSignature(SECRET, BODY, sig.toUpperCase())).toBe(false)
  })

  it('FINDING: an empty secret signs and verifies without complaint', () => {
    // Construction refuses an empty secret on an endpoint, but the exported
    // helpers are what a consumer calls, and they accept one.
    expect(verifyWebhookSignature('', BODY, signWebhookBody('', BODY))).toBe(true)
  })
})
