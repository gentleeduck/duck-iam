/**
 * `_resolveEndpoints` and `authedJson` both carry a SECURITY comment saying the endpoint's scheme is
 * checked before it reaches `fetch()`. Neither passed `redirect`, so `fetch` followed redirects by default
 * and the request did not necessarily land on the URL that was checked:
 *
 *  - a 307/308 from the token endpoint re-POSTs the body, which carries `client_secret`, to whatever the
 *    `Location` names;
 *  - a redirect to `http://` puts that secret, or the bearer token on the userinfo call, on the wire in
 *    plaintext, and `isHttpUrl` accepts `http:` so the check never spoke to this.
 *
 * `WebhookDispatcher._dispatch` already sets `redirect: 'error'`, with a comment giving the same reason:
 * "a remote could otherwise 30x-redirect to an internal IP nothing approved". Every outbound request in
 * the library now takes that posture.
 */
import { describe, expect, it } from 'vitest'
import { OAuthClient } from '../client'

/** Records every request init the client makes, answering a valid token/profile body. */
function recordingClient() {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = []
  const fetch = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ init, url: String(url) })
    return new Response(JSON.stringify({ access_token: 'at', sub: 'u1', token_type: 'bearer' }), {
      headers: { 'content-type': 'application/json' },
      status: 200,
    })
  }
  const client = new OAuthClient({
    clientId: 'cid',
    clientSecret: 'shhh',
    endpoints: {
      authorizationEndpoint: 'https://idp.example.com/authorize',
      tokenEndpoint: 'https://idp.example.com/token',
      userinfoEndpoint: 'https://idp.example.com/userinfo',
    },
    fetch,
    scopes: ['openid'],
  })
  return { calls, client }
}

describe('no outbound oauth request follows a redirect off the endpoint that was checked', () => {
  it('refuses a redirect on the code exchange, which posts client_secret', async () => {
    const { calls, client } = recordingClient()
    await client.exchangeCode({ code: 'c', codeVerifier: 'v', redirectUri: 'https://app.example.com/cb' })
    expect(calls).toHaveLength(1)
    expect(calls[0]?.init?.redirect).toBe('error')
    // The thing a 307 would carry along, named so the test says why it matters.
    expect(String(calls[0]?.init?.body)).toContain('client_secret=shhh')
  })

  it('refuses a redirect on refresh, which posts client_secret too', async () => {
    const { calls, client } = recordingClient()
    await client.refresh('rt')
    expect(calls[0]?.init?.redirect).toBe('error')
    expect(String(calls[0]?.init?.body)).toContain('client_secret=shhh')
  })

  it('refuses a redirect on userinfo, which sends the access token', async () => {
    const { calls, client } = recordingClient()
    await client.userinfo('at')
    expect(calls[0]?.init?.redirect).toBe('error')
  })

  it('refuses a redirect on a host-supplied authedJson url', async () => {
    const { calls, client } = recordingClient()
    await client.authedJson('https://api.example.com/user/emails', 'at')
    expect(calls[0]?.init?.redirect).toBe('error')
  })

  it('still rejects a non-http endpoint before any of this', async () => {
    // The scheme guard is the other half and must not have been traded away for the redirect one.
    const client = new OAuthClient({
      clientId: 'cid',
      endpoints: {
        authorizationEndpoint: 'https://idp.example.com/authorize',
        tokenEndpoint: 'file:///etc/passwd',
      },
      fetch: async () => new Response('{}'),
      scopes: ['openid'],
    })
    await expect(
      client.exchangeCode({ code: 'c', codeVerifier: 'v', redirectUri: 'https://app.example.com/cb' }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })
})
