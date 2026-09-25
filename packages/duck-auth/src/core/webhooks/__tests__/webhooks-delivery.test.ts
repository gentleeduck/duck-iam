/**
 * The webhook deliverer is the one place the library makes an outbound request
 * to an address a consumer chose, which makes it the library's SSRF surface, and
 * it is attached to the event bus, which makes its latency the authentication
 * flow's latency. Both of those are pinned here.
 */
import { describe, expect, it, vi } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { signWebhookBody, verifyWebhookSignature, WebhookDeliverer } from '../index'
import { backoffFor } from '../webhooks.constants'

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

  it('refuses the fully qualified and subdomain spellings of a reserved name', () => {
    for (const host of ['localhost.', 'api.localhost', 'printer.local', 'db.local.']) {
      expect(() => construct(`https://${host}/hook`)).toThrow()
    }
  })

  it('refuses the whole fc00::/7 unique-local range, brackets and all', () => {
    for (const host of ['[fc00::1]', '[fd12:3456::1]', '[fdff:ffff::]']) {
      expect(() => construct(`https://${host}/hook`)).toThrow()
    }
  })

  it('refuses every address in fe80::/10, not only the literal fe80:: prefix', () => {
    for (const host of ['[febf::1]', '[fe80:1::1]', '[feaa::1]']) {
      expect(() => construct(`https://${host}/hook`)).toThrow()
    }
  })

  it('admits a name that resolves inward until a resolver is wired, then refuses it', async () => {
    // Construction sees a string, so a name pointing at 127.0.0.1 passes it by construction.
    expect(() => construct('https://localtest.me/hook')).not.toThrow()

    const { deliverer, calls } = makeDeliverer({
      endpoints: [{ secret: SECRET, url: 'https://localtest.me/hook' }],
      maxAttempts: 1,
      resolveHost: async () => ['127.0.0.1'],
    })
    const [outcome] = await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(0)
    expect(outcome?.delivered).toBe(false)
    expect(outcome?.lastError).toMatch(/SSRF guard/)
  })

  it('delivers to a name that resolves outward', async () => {
    const { deliverer, calls } = makeDeliverer({ resolveHost: async () => ['93.184.216.34'] })
    const [outcome] = await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(1)
    expect(outcome?.delivered).toBe(true)
  })

  it('admits a public name that merely begins with a blocked address label', () => {
    for (const host of ['10.example.com', '0.example.com', '127.hooks.example', '0x7f.example.com']) {
      expect(() => construct(`https://${host}/hook`)).not.toThrow()
    }
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

  it('refuses userinfo in the endpoint url rather than sending it on every request', () => {
    for (const url of ['https://user:pass@hooks.example.com/hook', 'https://user@hooks.example.com/hook']) {
      expect(() => construct(url)).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
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
  it('releases the emitting flow before the retry ladder has run', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer(
      { backoffMs: 20, maxAttempts: 4 },
      () => new Response('', { status: 500 }),
    )
    const off = deliverer.attach(bus)

    const started = Date.now()
    await bus.emit('signup.completed', { identity: makeIdentity({ id: 'u' }) })
    const elapsed = Date.now() - started

    // The sign-in that emitted the event is not waiting on three backoffs.
    expect(elapsed).toBeLessThan(60)
    await deliverer.drain()
    expect(calls).toHaveLength(4)
    off()
  })

  it('does not hold the caller open for the dead-letter write either', async () => {
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

    await bus.emit('authz.revoked', { at: 0, identityId: 'u' })
    expect(sunk).toBe(false)
    await deliverer.drain()
    expect(sunk).toBe(true)
  })

  it('an unsubscribed deliverer stops receiving events', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer()
    const off = deliverer.attach(bus)
    off()
    await bus.emit('lockout', { identityId: 'u', until: 0 })
    expect(calls).toHaveLength(0)
  })

  it('attaching the same bus twice is the same subscription, and one cleanup detaches it', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer()
    const first = deliverer.attach(bus)
    const second = deliverer.attach(bus)
    expect(second).toBe(first)

    await bus.emit('lockout', { identityId: 'u', until: 0 })
    await deliverer.drain()
    expect(calls).toHaveLength(1)

    first()
    await bus.emit('lockout', { identityId: 'u', until: 0 })
    await deliverer.drain()
    expect(calls).toHaveLength(1)
  })

  it('a wildcard endpoint receives every name in the event map', async () => {
    // `EVERY_EVENT` is keyed off `Events.EventMap`, so a name added to the map and not to the list
    // fails to compile rather than silently dropping out of a `'*'` subscription.
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer({ endpoints: [{ events: '*', secret: SECRET, url: URL_OK }] })
    deliverer.attach(bus)

    await bus.emit('authz.revoked', { at: Date.now(), identityId: 'u' })
    await deliverer.drain()
    expect(calls).toHaveLength(1)

    await bus.emit('lockout', { identityId: 'u', until: 0 })
    await deliverer.drain()
    expect(calls).toHaveLength(2)
  })

  it('an endpoint naming a subset receives only that subset', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer({
      endpoints: [{ events: ['authz.revoked'], secret: SECRET, url: URL_OK }],
    })
    deliverer.attach(bus)
    await bus.emit('lockout', { identityId: 'u', until: 0 })
    await bus.emit('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(1)
  })

  it('an endpoint naming an empty event list receives nothing', async () => {
    const bus = new InMemoryEvents()
    const { deliverer, calls } = makeDeliverer({ endpoints: [{ events: [], secret: SECRET, url: URL_OK }] })
    deliverer.attach(bus)
    await bus.emit('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(0)
  })
})

describe('the retry loop cannot tell a transient failure from a permanent one', () => {
  it('stops after one attempt on a 4xx, which answers the same however often it is asked', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 5 }, () => new Response('', { status: 400 }))
    const [outcome] = await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(1)
    expect(outcome).toMatchObject({ delivered: false, lastError: 'non-2xx response (400)' })
  })

  it('stops after one attempt on a 410 Gone', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 3 }, () => new Response('', { status: 410 }))
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(1)
  })

  it('still spends the full ladder on the two 4xx codes that mean "later"', async () => {
    for (const status of [408, 429]) {
      const { deliverer, calls } = makeDeliverer({ maxAttempts: 3 }, () => new Response('', { status }))
      await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
      expect(calls).toHaveLength(3)
    }
  })

  it('still retries a 5xx, which is the failure that does clear', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 4 }, () => new Response('', { status: 503 }))
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(4)
  })

  it('dead-letters an oversize payload after one attempt, since the size cannot change', async () => {
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
    expect(spy).toHaveBeenCalledTimes(1)
    spy.mockRestore()
  })

  it('measures the payload cap in the utf-8 bytes actually sent', async () => {
    // `body.length` counts utf-16 code units, so a body of astral characters used to pass a 1 MiB
    // cap while putting over two megabytes on the wire.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const { deliverer, calls } = makeDeliverer()
    const emoji = '🐤'.repeat(300_000) // 600k code units, 1.2 MB of utf-8.
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: emoji })

    expect(calls).toHaveLength(0)
    spy.mockRestore()
  })

  it('stops at the first success and does not keep retrying', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 5 }, (n) =>
      n < 3 ? new Response('', { status: 500 }) : new Response('', { status: 200 }),
    )
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls).toHaveLength(3)
  })

  it('treats a 204 as delivered', async () => {
    const { deliverer, calls } = makeDeliverer({ maxAttempts: 3 }, () => new Response(null, { status: 204 }))
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
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
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
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
    // The sink's own failure stays swallowed - but the delivery failure it was
    // handed does not: the caller is still told the event never landed.
    const [outcome] = await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(outcome).toMatchObject({ delivered: false, lastError: 'non-2xx response (500)' })
  })

  it('reports a permanently failed event even with no dead-letter sink', async () => {
    // Was pinned as a finding: with no sink there was no log and no return
    // value, so a delivery that never happened was indistinguishable from one
    // that did. `deliverOne` now answers per endpoint, so the operator running
    // a manual re-delivery can see it failed without configuring a sink.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const { deliverer } = makeDeliverer({ maxAttempts: 1 }, () => new Response('', { status: 500 }))

    const outcomes = await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })

    expect(outcomes).toEqual([
      { attempts: 1, delivered: false, endpointId: expect.any(String), lastError: 'non-2xx response (500)' },
    ])
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })

  it('reports a delivered event as delivered, with the attempts it took (control)', async () => {
    // Without this the refusal above would also pass against a deliverer that
    // reported every event as failed.
    let calls = 0
    const { deliverer } = makeDeliverer({ maxAttempts: 3 }, () => {
      calls++
      return new Response('', { status: calls === 1 ? 500 : 200 })
    })

    const outcomes = await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })

    expect(outcomes).toEqual([{ attempts: 2, delivered: true, endpointId: expect.any(String) }])
  })

  it('clamps the attempt count into one through twenty', async () => {
    const zero = makeDeliverer({ maxAttempts: 0 }, () => new Response('', { status: 500 }))
    await zero.deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(zero.calls).toHaveLength(1)
  })

  it('refuses a backoff base that would floor every wait to zero or overflow the timer', () => {
    // A negative base makes every computed wait negative, and a base past 2^31 doubles out of the
    // timer's range on the first retry. `setTimeout` fires both immediately, so the ladder that
    // exists to spare a struggling consumer hammers it instead.
    for (const backoffMs of [-1000, 2 ** 32, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => makeDeliverer({ backoffMs })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
    expect(() => makeDeliverer({ backoffMs: 0 })).not.toThrow()
  })

  it('spreads each retry over the lower half of its interval, so a fleet does not retry in lockstep', () => {
    // Asserted on the schedule rather than on wall time: measuring a 15ms sleep is what made the
    // old version of this test flake, and jitter is a property of the number, not of the clock.
    const base = 1_000
    for (const attempt of [1, 2, 3]) {
      const ceiling = base * 2 ** (attempt - 1)
      expect(backoffFor(base, attempt, () => 0)).toBe(ceiling / 2)
      expect(backoffFor(base, attempt, () => 0.999)).toBeLessThan(ceiling)
      expect(backoffFor(base, attempt, () => 0.999)).toBeGreaterThan(ceiling / 2)
    }
    const spread = new Set(Array.from({ length: 50 }, () => backoffFor(base, 4)))
    expect(spread.size).toBeGreaterThan(40)
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
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
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
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(ok).toEqual(['https://b.example.com/h'])
  })
})

describe('what actually goes on the wire', () => {
  it('refuses to follow a redirect, so the guarded host stays the host', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(calls[0]?.init.redirect).toBe('error')
  })

  it('sends the signature and the timestamp it was computed over', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'hi' })

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

  it('blanks every secret-bearing key before the payload is signed or sent', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('session.created', {
      identity: makeIdentity({ id: 'u' }),
      session: makeSession({ id: 'sid', identityId: 'u' }),
    })
    const body = JSON.parse(calls[0]?.init.body as string)
    // The identifying fields still reach the consumer; the credentials do not.
    expect(body.payload.session).toMatchObject({ id: 'sid' })
    expect(body.payload.identity).toMatchObject({ id: 'u' })
    expect(JSON.stringify(body)).not.toMatch(/"(tokenHash|passwordHash|refreshToken|secret)":"(?!\[redacted\])/)
  })

  it('redacts nested credentials at any depth, and leaves the rest alone', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('suspicious', {
      meta: { inner: { apiKey: 'live_xyz', label: 'keep' }, sessionToken: 'tok' },
      score: 1,
      signal: 'test',
    } as never)
    const { payload } = JSON.parse(calls[0]?.init.body as string)
    expect(payload.meta.sessionToken).toBe('[redacted]')
    expect(payload.meta.inner.apiKey).toBe('[redacted]')
    expect(payload.meta.inner.label).toBe('keep')
    expect(payload.signal).toBe('test')
  })

  it('takes a caller-supplied redactor in place of the default', async () => {
    const { deliverer, calls } = makeDeliverer({ redact: () => ({ only: 'this' }) })
    await deliverer.deliverOne('authz.revoked', { secret: 'x' } as never)
    expect(JSON.parse(calls[0]?.init.body as string).payload).toEqual({ only: 'this' })
  })

  it('dead-letters an unserialisable payload without spending an attempt on it', async () => {
    // The body is built once, before the first attempt. Inside the loop a circular payload read as
    // a failed transport attempt, so nothing was ever sent and the caller still waited through
    // every backoff for an answer that could not change.
    const entries: Array<{ attempts: number; lastError: string }> = []
    const { deliverer, calls } = makeDeliverer({
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      maxAttempts: 3,
    })
    // A BigInt rather than a cycle: redaction truncates at its depth cap, so a cycle no longer
    // survives into the body (see the case below). A value `JSON.stringify` refuses outright still
    // does, which is the property this case is here for.
    const [outcome] = await deliverer.deliverOne('authz.revoked', { n: 1n } as never)
    expect(calls).toHaveLength(0)
    expect(outcome).toMatchObject({ attempts: 0, delivered: false })
    expect(entries[0]).toMatchObject({ attempts: 0 })
    expect(entries[0]?.lastError).toMatch(/serialize|circular|convert/i)
  })

  it('delivers a self-referencing payload truncated, rather than dead-lettering it', async () => {
    // A consequence of redaction failing closed at its depth cap: the cycle is cut there, so the body
    // serialises. Truncation is the cap's contract for any deep payload, and a cycle is just the
    // deepest one - delivering it truncated beats dead-lettering a hook the operator is waiting on.
    const { deliverer, calls } = makeDeliverer({})
    const circular: Record<string, unknown> = {}
    circular.self = circular

    const [outcome] = await deliverer.deliverOne('authz.revoked', circular as never)
    expect(outcome).toMatchObject({ delivered: true })
    expect(JSON.parse(calls[0]?.init.body as string).payload).toBeDefined()
  })

  it('treats a bigint the same way, and spends no attempt on it either', async () => {
    const entries: Array<{ attempts: number }> = []
    const { deliverer, calls } = makeDeliverer({
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      maxAttempts: 2,
    })
    await deliverer.deliverOne('authz.revoked', { message: 1n } as never)
    expect(calls).toHaveLength(0)
    expect(entries).toHaveLength(1)
    expect(entries[0]?.attempts).toBe(0)
  })

  it('honours a custom signature header name', async () => {
    const { deliverer, calls } = makeDeliverer({
      endpoints: [{ secret: SECRET, signatureHeader: 'X-Custom', url: URL_OK }],
    })
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect((calls[0]?.init.headers as Record<string, string>)['X-Custom']).toMatch(/^authSha256=/)
  })

  it('refuses a signature header name that fetch could never send', () => {
    for (const signatureHeader of ['X Bad: Header', 'X-Bad:', 'has space', '']) {
      expect(
        () =>
          new WebhookDeliverer({
            endpoints: [{ secret: SECRET, signatureHeader, url: URL_OK }],
            fetch: globalThis.fetch,
          }),
      ).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
    expect(
      () =>
        new WebhookDeliverer({
          endpoints: [{ secret: SECRET, signatureHeader: 'X-Custom', url: URL_OK }],
          fetch: globalThis.fetch,
        }),
    ).not.toThrow()
  })

  it('records the endpoint without the part of the url that authorises a request to it', async () => {
    const entries: Array<{ endpointId: string; endpointUrl: string }> = []
    const deliverer = new WebhookDeliverer({
      backoffMs: 0,
      deadLetter: {
        put: async (e) => {
          entries.push(e)
        },
      },
      endpoints: [{ secret: SECRET, url: 'https://hooks.example.com/h?token=hunter2#frag' }],
      fetch: (async () => new Response('', { status: 500 })) as never,
      maxAttempts: 1,
    })
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    expect(entries[0]?.endpointUrl).toBe('https://hooks.example.com/h')
    expect(entries[0]?.endpointId).toBe('https://hooks.example.com/h')
  })
})

describe('signature verification', () => {
  const BODY = '{"event":"authz.revoked"}'

  it('round-trips and rejects a tampered body', () => {
    const sig = signWebhookBody(SECRET, BODY)
    expect(verifyWebhookSignature(SECRET, BODY, sig)).toBe(true)
    expect(verifyWebhookSignature(SECRET, `${BODY} `, sig)).toBe(false)
  })

  it('rejects the right signature under the wrong secret', () => {
    expect(verifyWebhookSignature('other', BODY, signWebhookBody(SECRET, BODY))).toBe(false)
  })

  it('signs with its own prefix and verifies either spelling of it', () => {
    // The wire format stays `authSha256=`, because the GitHub and Stripe `sha256=` carries a
    // different payload under the same name and a verifier reading the prefix as theirs would
    // check the wrong string. Accepting both on the way in costs nothing: the digest is the same.
    const sig = signWebhookBody(SECRET, BODY)
    expect(sig.startsWith('authSha256=')).toBe(true)
    expect(verifyWebhookSignature(SECRET, BODY, sig)).toBe(true)
    expect(verifyWebhookSignature(SECRET, BODY, sig.replace('authSha256=', 'sha256='))).toBe(true)
    expect(verifyWebhookSignature(SECRET, BODY, sig.replace('authSha256=', ''))).toBe(false)
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

  it('refuses a negative or non-finite tolerance rather than rejecting every delivery under it', () => {
    // `Math.abs(...) > negative` is true for any gap at all, so a sign error in a consumer's config
    // would present as every delivery failing its signature check.
    const ts = Date.now()
    const sig = signWebhookBody(SECRET, BODY, ts)
    for (const toleranceMs of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => verifyWebhookSignature(SECRET, BODY, sig, { timestamp: ts, toleranceMs })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('carries a per-delivery id, in the signed body and in a header, for a consumer to key on', async () => {
    // A stateless verify cannot be single-use: the timestamp bounds a replay, and the id is what a
    // handler that must act once per delivery puts in its idempotency store.
    const { deliverer, calls } = makeDeliverer(
      { maxAttempts: 2 },
      (n) => new Response('', { status: n === 1 ? 500 : 200 }),
    )
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })

    const ids = calls.map((c) => (c.init.headers as Record<string, string>)['x-duck-delivery-id'])
    // The two attempts at the same delivery share an id; a second delivery gets its own.
    expect(ids[0]).toBe(ids[1])
    expect(ids[2]).not.toBe(ids[0])
    expect(JSON.parse(calls[0]?.init.body as string).deliveryId).toBe(ids[0])
  })

  it('signs the timestamp it sends, so neither the header nor the body can be swapped', async () => {
    const { deliverer, calls } = makeDeliverer()
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    const header = Number((calls[0]?.init.headers as Record<string, string>)['x-duck-timestamp'])
    const body = calls[0]?.init.body as string

    const signature = (calls[0]?.init.headers as Record<string, string>)['X-Duck-Signature'] as string
    expect(verifyWebhookSignature(SECRET, body, signature, { timestamp: header })).toBe(true)
    // Altering the header alone breaks the HMAC, because the signature covers it.
    expect(verifyWebhookSignature(SECRET, body, signature, { timestamp: header - 1 })).toBe(false)
    // And the body with it: the HMAC is over `sentAt` and these bytes together, which is what binds the
    // pair. They are not required to be equal - the header is when this attempt left, the body's
    // `timestamp` is when the event was raised, and on a retry those are different moments.
    expect(verifyWebhookSignature(SECRET, `${body} `, signature, { timestamp: header })).toBe(false)
  })

  it('stamps each attempt as it is sent, so a retry is not stale when it lands', async () => {
    // A ladder scaled down to keep the test quick; the shape is the one `backoffMs: 60_000` produces at
    // full size, where attempt 5 is 7.5 minutes out against a 5 minute default tolerance.
    const verdicts: boolean[] = []
    const stamps: number[] = []
    const fetchStub = (async (_url: unknown, init: unknown) => {
      const { body, headers } = init as { body: string; headers: Record<string, string> }
      const timestamp = Number(headers['x-duck-timestamp'])
      stamps.push(timestamp)
      verdicts.push(
        verifyWebhookSignature(SECRET, body, headers['X-Duck-Signature'] as string, {
          timestamp,
          toleranceMs: 100,
        }),
      )
      return new Response('nope', { status: 500 })
    }) as unknown as typeof globalThis.fetch

    const deliverer = new WebhookDeliverer({
      backoffMs: 40,
      endpoints: [{ secret: SECRET, url: URL_OK }],
      fetch: fetchStub,
      maxAttempts: 5,
      random: () => 0,
    })
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })

    // The live control: the ladder really did outrun the tolerance, so an unchanged stamp would have
    // failed here rather than the whole run finishing inside 100ms.
    expect(stamps.at(-1)! - stamps[0]!).toBeGreaterThan(100)
    expect(verdicts).toEqual([true, true, true, true, true])
  })

  it('keeps the body byte-identical across a retry, so idempotency still keys on one delivery', async () => {
    const { calls, deliverer } = makeDeliverer({ maxAttempts: 3 }, () => new Response('nope', { status: 500 }))
    await deliverer.deliverOne('authz.revoked', { at: 0, identityId: 'u' })
    const bodies = calls.map((c) => c.init.body as string)
    expect(bodies).toHaveLength(3)
    expect(new Set(bodies).size).toBe(1)
  })

  it('rejects a signature of a different length without comparing it', () => {
    expect(verifyWebhookSignature(SECRET, BODY, 'authSha256=short')).toBe(false)
    expect(verifyWebhookSignature(SECRET, BODY, '')).toBe(false)
  })

  it('rejects a signature that differs only in case', () => {
    const sig = signWebhookBody(SECRET, BODY)
    expect(verifyWebhookSignature(SECRET, BODY, sig.toUpperCase())).toBe(false)
  })

  it('refuses an empty secret in the exported helpers, not only at construction', () => {
    for (const secret of ['', null as never, undefined as never]) {
      expect(() => signWebhookBody(secret, BODY)).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
      expect(() => verifyWebhookSignature(secret, BODY, 'authSha256=x')).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })
})
