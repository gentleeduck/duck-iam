/**
 * The siteverify POST carries the captcha `secret` in its body, and `resolveCaptchaCfg` runs the endpoint
 * through `assertSafeOutboundUrl` for exactly that reason — "the secret is posted to whatever this points
 * at". The fetch passed no `redirect`, so a 307 from the endpoint re-posts that body, secret and all, to a
 * host the guard never saw, and a redirect to `http://` puts it on the wire in plaintext.
 */
import { describe, expect, it } from 'vitest'
import { AuthTurnstileVerifier } from '../captcha'

describe('the captcha siteverify POST does not follow a redirect', () => {
  it('sends redirect: error, and the secret that makes it matter', async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = []
    const verifier = new AuthTurnstileVerifier({
      fetch: async (url: string | URL | Request, init?: RequestInit) => {
        calls.push({ init, url: String(url) })
        return new Response(JSON.stringify({ success: true }), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        })
      },
      secret: 'shhh',
    })
    await verifier.verify({ token: 't' })
    expect(calls).toHaveLength(1)
    expect(calls[0]?.init?.redirect).toBe('error')
    expect(String(calls[0]?.init?.body)).toContain('secret=shhh')
  })
})
