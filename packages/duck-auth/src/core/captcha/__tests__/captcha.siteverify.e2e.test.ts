/** E2E: the siteverify POST over a real socket, where the peer chooses the status, the redirects and the stalls. */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { AuthTurnstileVerifier } from '../index'

type Answer = (req: IncomingMessage, res: ServerResponse) => void

describe('E2E siteverify against a real HTTP peer', () => {
  const seen: Array<{ body: Record<string, string>; contentType?: string; method?: string; path?: string }> = []
  let answer: Answer = () => {}
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk)
    const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))
    seen.push({ body, contentType: req.headers['content-type'], method: req.method, path: req.url })
    answer(req, res)
  })
  let peer = ''

  /** The real `fetch`, re-aimed at the peer. The endpoint guard refuses loopback, so the verifier keeps its
   *  default endpoint, which is what the guard vetted, and only the socket moves. */
  const toPeer: typeof fetch = (url, init) => fetch(new URL(new URL(String(url)).pathname, peer), init)

  const json =
    (status: number, body: unknown): Answer =>
    (_req, res) => {
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body))
    }

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (address === null || typeof address === 'string') throw new Error('the peer is not on a port')
    peer = `http://127.0.0.1:${address.port}`
  })

  beforeEach(() => {
    seen.length = 0
  })

  // Only once done: a socket closed between cases is one `fetch` may still reuse, and fail on for that alone.
  afterAll(async () => {
    server.closeAllConnections()
    await new Promise((resolve) => server.close(resolve))
  })

  it('posts the form to the provider path and passes a valid answer', async () => {
    answer = json(200, { challenge_ts: new Date().toISOString(), hostname: 'app.example.com', success: true })
    const verifier = new AuthTurnstileVerifier({ expectedHostname: 'app.example.com', fetch: toPeer, secret: 'sk' })

    expect(await verifier.verify({ remoteIp: '203.0.113.9', token: 'the-token' })).toMatchObject({
      hostname: 'app.example.com',
      success: true,
    })
    expect(seen).toEqual([
      {
        body: { remoteip: '203.0.113.9', response: 'the-token', secret: 'sk' },
        contentType: 'application/x-www-form-urlencoded',
        method: 'POST',
        path: '/turnstile/v0/siteverify',
      },
    ])
    // The same answer, solved on a host nobody expected.
    const elsewhere = new AuthTurnstileVerifier({ expectedHostname: 'other.example', fetch: toPeer, secret: 'sk' })
    expect(await elsewhere.verify({ token: 't' })).toMatchObject({ errorCodes: ['hostname-mismatch'], success: false })
  })

  it('refuses a real 307 without re-posting the secret to where it points', async () => {
    answer = (req, res) => {
      if (req.url === '/elsewhere') json(200, { success: true })(req, res)
      else res.writeHead(307, { location: '/elsewhere' }).end()
    }
    const verifier = new AuthTurnstileVerifier({ fetch: toPeer, secret: 'sk' })

    expect(await verifier.verify({ token: 't' })).toMatchObject({ errorCodes: ['network-error'], success: false })
    expect(seen.map((s) => s.path)).toEqual(['/turnstile/v0/siteverify'])
  })

  it.each<[string, Answer]>([
    ['before the status line', () => {}],
    [
      'halfway through the body',
      (_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' }).write('{"success":')
      },
    ],
  ])('times out a peer that stalls %s', async (_, stall) => {
    answer = stall
    const verifier = new AuthTurnstileVerifier({ fetch: toPeer, secret: 'sk', timeoutMs: 200 })

    expect(await verifier.verify({ token: 't' })).toEqual({ errorCodes: ['timeout'], success: false })
  })

  it('fails closed on a status that is not 2xx, whatever its body says', async () => {
    answer = json(503, { success: true })
    const verifier = new AuthTurnstileVerifier({ fetch: toPeer, secret: 'sk' })

    expect(await verifier.verify({ token: 't' })).toEqual({ errorCodes: ['provider-http-503'], success: false })
  })

  it('fails closed on a page answered 200, the captive-portal case', async () => {
    answer = (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' }).end('<html>Sign in to the wifi</html>')
    }
    const verifier = new AuthTurnstileVerifier({ fetch: toPeer, secret: 'sk' })

    expect(await verifier.verify({ token: 't' })).toEqual({ errorCodes: ['malformed-response'], success: false })
  })

  it('reports a body the socket dropped as a network failure, not as a malformed answer', async () => {
    answer = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' }).write('{"success":', () => res.destroy())
    }
    const verifier = new AuthTurnstileVerifier({ fetch: toPeer, secret: 'sk' })

    expect(await verifier.verify({ token: 't' })).toEqual({
      detail: expect.any(String),
      errorCodes: ['network-error'],
      success: false,
    })
  })
})
