import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  authBuildOidcDiscovery,
  authBuildOidcRoutes,
  authCfgureOidcDiscoveryCache,
  authConfigureOidcDiscoveryCache,
  authFetchOidcDiscovery,
  authFlushOidcDiscoveryCache,
} from '../index'

describe('authBuildOidcDiscovery', () => {
  it('refuses missing issuer', () => {
    expect(() => authBuildOidcDiscovery({ issuer: '' })).toThrowError(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('emits required OIDC discovery fields', () => {
    const d = authBuildOidcDiscovery({ issuer: 'https://app.test' })
    expect(d.issuer).toBe('https://app.test')
    expect(d.jwks_uri).toBe('https://app.test/.well-known/jwks.json')
    expect(d.authorization_endpoint).toBe('https://app.test/auth/oauth/authorize')
    expect(d.token_endpoint).toBe('https://app.test/auth/oauth/token')
    expect(d.code_challenge_methods_supported).toEqual(['S256'])
    expect(d.subject_types_supported).toEqual(['public'])
  })

  it('exposes introspection + revocation endpoints out of the box', () => {
    const d = authBuildOidcDiscovery({ issuer: 'https://app.test' })
    expect(d.introspection_endpoint).toBe('https://app.test/auth/oauth/introspect')
    expect(d.revocation_endpoint).toBe('https://app.test/auth/oauth/revoke')
  })

  it('only emits registration_endpoint when explicitly opted-in', () => {
    const off = authBuildOidcDiscovery({ issuer: 'https://app.test' })
    expect(off.registration_endpoint).toBeUndefined()
    const on = authBuildOidcDiscovery({
      issuer: 'https://app.test',
      registrationEndpoint: 'https://app.test/auth/oauth/register',
    })
    expect(on.registration_endpoint).toBe('https://app.test/auth/oauth/register')
  })

  it('strips trailing slash from issuer', () => {
    const d = authBuildOidcDiscovery({ issuer: 'https://app.test/' })
    expect(d.issuer).toBe('https://app.test')
    expect(d.token_endpoint).toBe('https://app.test/auth/oauth/token')
  })

  it('refuses a prefix or jwksPath without its leading slash, which put the endpoints on another host', () => {
    for (const cfg of [{ prefix: 'auth' }, { jwksPath: 'jwks.json' }, { jwksPath: '.evil.example/jwks' }]) {
      expect(() => authBuildOidcDiscovery({ issuer: 'https://app.test', ...cfg })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
    expect(authBuildOidcDiscovery({ issuer: 'https://app.test', prefix: '' }).token_endpoint).toBe(
      'https://app.test/oauth/token',
    )
    // Dropped like the issuer's, or every endpoint carried a `//` no route matches.
    expect(authBuildOidcDiscovery({ issuer: 'https://app.test', prefix: '/auth/' }).token_endpoint).toBe(
      'https://app.test/auth/oauth/token',
    )
  })

  it('respects custom prefix + jwksPath + algs', () => {
    const d = authBuildOidcDiscovery({
      issuer: 'https://app.test',
      prefix: '/v2/auth',
      jwksPath: '/keys.json',
      signingAlgs: ['ES256', 'RS256'],
    })
    expect(d.token_endpoint).toBe('https://app.test/v2/auth/oauth/token')
    expect(d.jwks_uri).toBe('https://app.test/keys.json')
    expect(d.id_token_signing_alg_values_supported).toEqual(['ES256', 'RS256'])
  })

  it('extraClaims merges into the top-level document', () => {
    const d = authBuildOidcDiscovery({
      issuer: 'https://app.test',
      extraClaims: { service_documentation: 'https://app.test/docs/auth' },
    })
    expect(d.service_documentation).toBe('https://app.test/docs/auth')
  })

  it('extraClaims cannot shadow canonical fields (issuer/jwks_uri/etc)', () => {
    const d = authBuildOidcDiscovery({
      issuer: 'https://legit.test',
      extraClaims: {
        issuer: 'https://attacker.test',
        jwks_uri: 'https://attacker.test/keys',
        token_endpoint: 'https://attacker.test/oauth/token',
      },
    })
    expect(d.issuer).toBe('https://legit.test')
    expect(d.jwks_uri).toBe('https://legit.test/.well-known/jwks.json')
    expect(d.token_endpoint).toBe('https://legit.test/auth/oauth/token')
  })

  it('refuses non-HTTPS issuer unless allowHttp is set', () => {
    try {
      authBuildOidcDiscovery({ issuer: 'http://app.test' })
      throw new Error('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH_MISCONFIGURED')
      expect((err as { meta: { detail: string } }).meta.detail).toMatch(/HTTPS/)
    }
    const d = authBuildOidcDiscovery({ issuer: 'http://localhost:3000', allowHttp: true })
    expect(d.issuer).toBe('http://localhost:3000')
  })

  it("drops 'none' from token_endpoint_auth_methods_supported by default", () => {
    const d = authBuildOidcDiscovery({ issuer: 'https://app.test' })
    expect(d.token_endpoint_auth_methods_supported).not.toContain('none')
  })

  it("explicit tokenEndpointAuthMethodsSupported including 'none' is honored", () => {
    const d = authBuildOidcDiscovery({
      issuer: 'https://app.test',
      tokenEndpointAuthMethodsSupported: ['none', 'client_secret_basic'],
    })
    expect(d.token_endpoint_auth_methods_supported).toContain('none')
  })

  it('refuses invalid URL as issuer', () => {
    try {
      authBuildOidcDiscovery({ issuer: 'not a url' })
      throw new Error('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH_MISCONFIGURED')
      expect((err as { meta: { detail: string } }).meta.detail).toMatch(/not a valid URL/)
    }
  })
})

describe('authBuildOidcRoutes', () => {
  it('returns discovery + jwks pass-through', () => {
    const transport = {
      jwks: () => ({ keys: [{ kid: 'k1', kty: 'EC', alg: 'ES256' }] }),
    }
    const out = authBuildOidcRoutes({
      config: { issuer: 'https://app.test' },
      transport,
    })
    expect(out.discovery.issuer).toBe('https://app.test')
    expect(out.jwks.keys).toHaveLength(1)
    expect(out.jwks.keys[0]!.kid).toBe('k1')
  })
})

describe('authFetchOidcDiscovery - RP-side cache', () => {
  beforeEach(() => {
    authFlushOidcDiscoveryCache()
    authConfigureOidcDiscoveryCache({ ttlMs: 60_000, capacity: 4 })
  })

  it('fetches + caches the discovery document; second call does not hit the network', async () => {
    let fetches = 0
    const fakeFetch = vi.fn(async (url: string | URL | Request) => {
      fetches++
      return new Response(
        JSON.stringify({
          issuer: 'https://idp.test',
          authorization_endpoint: 'https://idp.test/auth',
          token_endpoint: 'https://idp.test/token',
          jwks_uri: 'https://idp.test/jwks',
          userinfo_endpoint: 'https://idp.test/userinfo',
          end_session_endpoint: 'https://idp.test/logout',
          scopes_supported: ['openid'],
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['ES256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic'],
          code_challenge_methods_supported: ['S256'],
        }),
        { status: 200 },
      )
    }) as unknown as typeof globalThis.fetch
    const a = await authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    const b = await authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    expect(a.issuer).toBe('https://idp.test')
    expect(b.issuer).toBe('https://idp.test')
    expect(fetches).toBe(1)
  })

  it('rejects upstream when the response issuer mismatches the requested issuer', async () => {
    // A WELL-FORMED discovery doc whose `issuer` claim is the attacker's.
    // The parser accepts the shape; the post-parse issuer-mismatch check
    // is what must fail closed.
    const fakeFetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            issuer: 'https://attacker.test',
            authorization_endpoint: 'https://attacker.test/auth',
            token_endpoint: 'https://attacker.test/token',
            userinfo_endpoint: 'https://attacker.test/userinfo',
            jwks_uri: 'https://attacker.test/jwks',
            end_session_endpoint: 'https://attacker.test/logout',
            scopes_supported: ['openid'],
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['ES256'],
            token_endpoint_auth_methods_supported: ['client_secret_basic'],
            code_challenge_methods_supported: ['S256'],
          }),
          { status: 200 },
        ),
    ) as unknown as typeof globalThis.fetch
    await expect(authFetchOidcDiscovery('https://legit.test', { fetch: fakeFetch })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('refuses non-HTTPS issuer unless allowHttp is set', async () => {
    await expect(authFetchOidcDiscovery('http://idp.test', { fetch: vi.fn() as never })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  /**
   * The fifth outbound path. `outbound-redirects.test.ts` pins the four on the
   * OAuth client and webhooks/captcha pin their own; discovery sets
   * `redirect: 'error'` for the same reason and was the one nobody asserted.
   *
   * It matters more here than on the others: the document this call returns
   * names the `token_endpoint` and `jwks_uri` the host will trust afterwards, so
   * a 302 to an attacker's well-known endpoint re-points both. The issuer check
   * cannot save it — the attacker's document would carry a matching `issuer`
   * claim for the host it redirected to.
   */
  it('refuses to follow a redirect, so the document comes from the issuer that was asked', async () => {
    const calls: Array<RequestInit | undefined> = []
    const fakeFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      calls.push(init)
      return new Response(
        JSON.stringify({
          issuer: 'https://idp.test',
          authorization_endpoint: 'https://idp.test/auth',
          token_endpoint: 'https://idp.test/token',
          jwks_uri: 'https://idp.test/jwks',
          scopes_supported: ['openid'],
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['ES256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic'],
          code_challenge_methods_supported: ['S256'],
        }),
        { status: 200 },
      )
    }) as unknown as typeof globalThis.fetch
    await authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    expect(calls).toHaveLength(1)
    expect(calls[0]?.redirect).toBe('error')
  })

  /**
   * The endpoints inside an accepted document are validated for shape and
   * nothing else: an issuer the host configured is trusted to name its own
   * endpoints, and no code in this package fetches them. Stated as a test
   * because the moment an issuer becomes tenant-supplied, or anything here
   * starts fetching `jwks_uri`, that trust has to be re-decided — the SSRF guard
   * in `core/url-validators` is what it would need, and discovery does not call it.
   */
  it('accepts a document whose own endpoints point at internal hosts, which is the host-trust boundary', async () => {
    const fakeFetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            issuer: 'https://idp.test',
            authorization_endpoint: 'https://idp.test/auth',
            token_endpoint: 'http://169.254.169.254/latest/meta-data/',
            jwks_uri: 'http://127.0.0.1:6379/',
            scopes_supported: ['openid'],
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['ES256'],
            token_endpoint_auth_methods_supported: ['client_secret_basic'],
            code_challenge_methods_supported: ['S256'],
          }),
          { status: 200 },
        ),
    ) as unknown as typeof globalThis.fetch
    const doc = await authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    expect(doc.token_endpoint).toBe('http://169.254.169.254/latest/meta-data/')
    expect(doc.jwks_uri).toBe('http://127.0.0.1:6379/')
  })

  it('bypassCache forces a re-fetch', async () => {
    let fetches = 0
    const fakeFetch = vi.fn(async () => {
      fetches++
      return new Response(
        JSON.stringify({
          issuer: 'https://idp.test',
          authorization_endpoint: 'https://idp.test/auth',
          token_endpoint: 'https://idp.test/token',
          jwks_uri: 'https://idp.test/jwks',
          userinfo_endpoint: 'https://idp.test/userinfo',
          end_session_endpoint: 'https://idp.test/logout',
          scopes_supported: ['openid'],
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['ES256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic'],
          code_challenge_methods_supported: ['S256'],
        }),
        { status: 200 },
      )
    }) as unknown as typeof globalThis.fetch
    await authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    await authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch, bypassCache: true })
    expect(fetches).toBe(2)
  })

  it('rejects a malformed discovery doc (missing required token_endpoint)', async () => {
    const fakeFetch = vi.fn(
      async () =>
        // Only issuer + jwks_uri - missing every other required field.
        // The legacy `as IDocument` cast would have silently accepted
        // this; parseDiscoveryDoc rejects.
        new Response(JSON.stringify({ issuer: 'https://idp.test', jwks_uri: 'https://idp.test/jwks' }), {
          status: 200,
        }),
    ) as unknown as typeof globalThis.fetch
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('rejects a discovery doc with a non-string token_endpoint', async () => {
    const fakeFetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            issuer: 'https://idp.test',
            authorization_endpoint: 'https://idp.test/auth',
            token_endpoint: 42, // <-- wrong type
            jwks_uri: 'https://idp.test/jwks',
            userinfo_endpoint: 'https://idp.test/userinfo',
            end_session_endpoint: 'https://idp.test/logout',
            scopes_supported: ['openid'],
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['ES256'],
            token_endpoint_auth_methods_supported: ['client_secret_basic'],
            code_challenge_methods_supported: ['S256'],
          }),
          { status: 200 },
        ),
    ) as unknown as typeof globalThis.fetch
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })
})

describe('authFetchOidcDiscovery - an issuer that is down, slow or answers garbage', () => {
  beforeEach(() => authFlushOidcDiscoveryCache())

  const DOC = {
    authorization_endpoint: 'https://idp.test/auth',
    code_challenge_methods_supported: ['S256'],
    end_session_endpoint: 'https://idp.test/logout',
    grant_types_supported: ['authorization_code'],
    id_token_signing_alg_values_supported: ['ES256'],
    issuer: 'https://idp.test',
    jwks_uri: 'https://idp.test/jwks',
    response_types_supported: ['code'],
    scopes_supported: ['openid'],
    subject_types_supported: ['public'],
    token_endpoint: 'https://idp.test/token',
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    userinfo_endpoint: 'https://idp.test/userinfo',
  }

  /** Answers a body `start` writes into, erroring it once the request's signal aborts, as fetch does. */
  const streaming =
    (start: (c: ReadableStreamDefaultController<Uint8Array>) => void): typeof globalThis.fetch =>
    async (_url, init) =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(c) {
            init?.signal?.addEventListener('abort', () => c.error(init.signal?.reason))
            start(c)
          },
        }),
      )

  const PROVIDER_FAILED = { code: 'AUTH_PROVIDER_FAILED' }

  it('gives up on an issuer that never answers', async () => {
    const fetch: typeof globalThis.fetch = (_url, init) =>
      new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal?.reason)))
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch, timeoutMs: 50 })).rejects.toMatchObject(
      PROVIDER_FAILED,
    )
  }, 2_000)

  it('gives up on a body that stops arriving', async () => {
    const fetch = streaming((c) => c.enqueue(new TextEncoder().encode('{"issuer":')))
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch, timeoutMs: 50 })).rejects.toMatchObject(
      PROVIDER_FAILED,
    )
  }, 2_000)

  it('answers a network failure and a body that is not JSON as the provider failing', async () => {
    const down: typeof globalThis.fetch = async () => {
      throw new TypeError('fetch failed')
    }
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch: down })).rejects.toMatchObject(PROVIDER_FAILED)
    const maintenance: typeof globalThis.fetch = async () => new Response('<html>maintenance</html>')
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch: maintenance })).rejects.toMatchObject(
      PROVIDER_FAILED,
    )
  })

  it('refuses a document past 64 KiB without reading the rest of it', async () => {
    // A valid document padded to 1 MiB, so one read whole would be accepted.
    const encoder = new TextEncoder()
    const chunks = [
      '{"padding":"',
      ...Array<string>(64).fill('a'.repeat(16 * 1024)),
      `",${JSON.stringify(DOC).slice(1)}`,
    ]
    let pulled = 0
    const fetch: typeof globalThis.fetch = async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(c) {
            const next = chunks.shift()
            if (next === undefined) return c.close()
            pulled += next.length
            c.enqueue(encoder.encode(next))
          },
        }),
      )
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch })).rejects.toMatchObject(PROVIDER_FAILED)
    expect(pulled).toBeLessThan(256 * 1024)
  })

  it('reads a document under the cap, padding and all', async () => {
    const fetch: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify({ ...DOC, padding: 'a'.repeat(60 * 1024) }))
    expect((await authFetchOidcDiscovery('https://idp.test', { fetch, timeoutMs: 1_000 })).token_endpoint).toBe(
      'https://idp.test/token',
    )
  })

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, 2_147_483_648])(
    'refuses a timeoutMs of %o',
    async (timeoutMs) => {
      const fetch: typeof globalThis.fetch = async () => new Response(JSON.stringify(DOC))
      await expect(authFetchOidcDiscovery('https://idp.test', { fetch, timeoutMs })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    },
  )
})

describe('authFetchOidcDiscovery - requires what OIDC Discovery 1.0 requires, and no more', () => {
  beforeEach(() => authFlushOidcDiscoveryCache())

  // Apple publishes no userinfo or end-session endpoint, no grant types and no PKCE methods; Google no end-session.
  const REQUIRED_ONLY = {
    authorization_endpoint: 'https://idp.test/auth',
    id_token_signing_alg_values_supported: ['RS256'],
    issuer: 'https://idp.test',
    jwks_uri: 'https://idp.test/jwks',
    response_types_supported: ['code'],
    subject_types_supported: ['pairwise'],
    token_endpoint: 'https://idp.test/token',
  }
  const serving =
    (doc: Record<string, unknown>): typeof globalThis.fetch =>
    async () =>
      new Response(JSON.stringify(doc))

  it('reads a document carrying only the required fields, each absent list holding the spec default', async () => {
    const doc = await authFetchOidcDiscovery('https://idp.test', { fetch: serving(REQUIRED_ONLY) })
    expect(doc).toMatchObject({
      code_challenge_methods_supported: [],
      grant_types_supported: ['authorization_code', 'implicit'],
      scopes_supported: ['openid'],
      token_endpoint: 'https://idp.test/token',
      token_endpoint_auth_methods_supported: ['client_secret_basic'],
    })
    expect(doc.userinfo_endpoint).toBeUndefined()
    expect(doc.end_session_endpoint).toBeUndefined()
  })

  it('keeps what an issuer does publish over the default', async () => {
    const doc = await authFetchOidcDiscovery('https://idp.test', {
      fetch: serving({
        ...REQUIRED_ONLY,
        code_challenge_methods_supported: ['S256'],
        end_session_endpoint: 'https://idp.test/logout',
        grant_types_supported: ['authorization_code'],
        revocation_endpoint: 'https://idp.test/revoke',
        userinfo_endpoint: 'https://idp.test/userinfo',
      }),
    })
    expect(doc).toMatchObject({
      code_challenge_methods_supported: ['S256'],
      end_session_endpoint: 'https://idp.test/logout',
      grant_types_supported: ['authorization_code'],
      revocation_endpoint: 'https://idp.test/revoke',
      userinfo_endpoint: 'https://idp.test/userinfo',
    })
  })

  it.each([
    ['userinfo_endpoint', null],
    ['end_session_endpoint', ''],
    ['revocation_endpoint', 42],
    ['introspection_endpoint', { url: 'https://idp.test/introspect' }],
    ['registration_endpoint', ['https://idp.test/register']],
    ['grant_types_supported', 'authorization_code'],
    ['code_challenge_methods_supported', [256]],
  ])('refuses an optional %s that is there but not the type it is declared as', async (key, value) => {
    await expect(
      authFetchOidcDiscovery('https://idp.test', { fetch: serving({ ...REQUIRED_ONLY, [key]: value }) }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it.each([
    'jwks_uri',
    'authorization_endpoint',
    'response_types_supported',
    'subject_types_supported',
    'id_token_signing_alg_values_supported',
  ])('still refuses a document without %s, which the spec requires', async (key) => {
    const doc: Record<string, unknown> = { ...REQUIRED_ONLY }
    delete doc[key]
    await expect(authFetchOidcDiscovery('https://idp.test', { fetch: serving(doc) })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })
})

describe('authConfigureOidcDiscoveryCache', () => {
  beforeEach(() => {
    authFlushOidcDiscoveryCache()
    authConfigureOidcDiscoveryCache({ capacity: 32, ttlMs: 60 * 60 * 1000 })
  })

  /** How many of `n` issuers a second pass over them fetches again. */
  const refetched = async (n: number): Promise<number> => {
    let fetches = 0
    const pass = async (): Promise<void> => {
      for (let i = 0; i < n; i++) {
        const issuer = `https://idp-${i}.test`
        const body = JSON.stringify({
          authorization_endpoint: `${issuer}/auth`,
          id_token_signing_alg_values_supported: ['RS256'],
          issuer,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          token_endpoint: `${issuer}/token`,
        })
        await authFetchOidcDiscovery(issuer, {
          fetch: async () => {
            fetches++
            return new Response(body)
          },
        })
      }
    }
    await pass()
    fetches = 0
    await pass()
    return fetches
  }

  it('refuses a capacity that is not a whole number, as an unset env var gives, which never evicted', () => {
    for (const capacity of [Number(undefined), -1, 1.5, Number.POSITIVE_INFINITY]) {
      expect(() => authConfigureOidcDiscoveryCache({ capacity })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('refuses a ttlMs that is not a number of milliseconds, which never cached', () => {
    for (const ttlMs of [Number(undefined), -1]) {
      expect(() => authConfigureOidcDiscoveryCache({ ttlMs })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('leaves the cache as it was after a refusal', async () => {
    authConfigureOidcDiscoveryCache({ capacity: 4 })
    expect(() => authConfigureOidcDiscoveryCache({ capacity: Number(undefined) })).toThrow()
    expect(await refetched(50)).toBe(50)
  })

  it('evicts past the capacity it was given, and keeps what fits', async () => {
    authConfigureOidcDiscoveryCache({ capacity: 4 })
    expect(await refetched(50)).toBe(50)
    authConfigureOidcDiscoveryCache({ capacity: 64 })
    expect(await refetched(50)).toBe(0)
  })

  it('still answers to the misspelled name every 5.x release since 5.1.0 exported', () => {
    expect(authCfgureOidcDiscoveryCache).toBe(authConfigureOidcDiscoveryCache)
  })
})
