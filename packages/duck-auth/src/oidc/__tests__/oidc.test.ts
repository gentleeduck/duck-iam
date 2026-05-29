import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  buildOidcDiscovery,
  buildOidcRoutes,
  configureOidcDiscoveryCache,
  fetchOidcDiscovery,
  flushOidcDiscoveryCache,
} from '../index'

describe('buildOidcDiscovery', () => {
  it('refuses missing issuer', () => {
    expect(() => buildOidcDiscovery({ issuer: '' })).toThrowError(
      expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }),
    )
  })

  it('emits required OIDC discovery fields', () => {
    const d = buildOidcDiscovery({ issuer: 'https://app.test' })
    expect(d.issuer).toBe('https://app.test')
    expect(d.jwks_uri).toBe('https://app.test/.well-known/jwks.json')
    expect(d.authorization_endpoint).toBe('https://app.test/auth/oauth/authorize')
    expect(d.token_endpoint).toBe('https://app.test/auth/oauth/token')
    expect(d.code_challenge_methods_supported).toEqual(['S256'])
    expect(d.subject_types_supported).toEqual(['public'])
  })

  it('strips trailing slash from issuer', () => {
    const d = buildOidcDiscovery({ issuer: 'https://app.test/' })
    expect(d.issuer).toBe('https://app.test')
    expect(d.token_endpoint).toBe('https://app.test/auth/oauth/token')
  })

  it('respects custom prefix + jwksPath + algs', () => {
    const d = buildOidcDiscovery({
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
    const d = buildOidcDiscovery({
      issuer: 'https://app.test',
      extraClaims: { service_documentation: 'https://app.test/docs/auth' },
    })
    expect(d.service_documentation).toBe('https://app.test/docs/auth')
  })

  it('extraClaims cannot shadow canonical fields (issuer/jwks_uri/etc)', () => {
    const d = buildOidcDiscovery({
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
      buildOidcDiscovery({ issuer: 'http://app.test' })
      throw new Error('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH/MISCONFIGURED')
      expect((err as { meta: { detail: string } }).meta.detail).toMatch(/HTTPS/)
    }
    const d = buildOidcDiscovery({ issuer: 'http://localhost:3000', allowHttp: true })
    expect(d.issuer).toBe('http://localhost:3000')
  })

  it("drops 'none' from token_endpoint_auth_methods_supported by default", () => {
    const d = buildOidcDiscovery({ issuer: 'https://app.test' })
    expect(d.token_endpoint_auth_methods_supported).not.toContain('none')
  })

  it("explicit tokenEndpointAuthMethodsSupported including 'none' is honored", () => {
    const d = buildOidcDiscovery({
      issuer: 'https://app.test',
      tokenEndpointAuthMethodsSupported: ['none', 'client_secret_basic'],
    })
    expect(d.token_endpoint_auth_methods_supported).toContain('none')
  })

  it('refuses invalid URL as issuer', () => {
    try {
      buildOidcDiscovery({ issuer: 'not a url' })
      throw new Error('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH/MISCONFIGURED')
      expect((err as { meta: { detail: string } }).meta.detail).toMatch(/not a valid URL/)
    }
  })
})

describe('buildOidcRoutes', () => {
  it('returns discovery + jwks pass-through', () => {
    const transport = {
      jwks: () => ({ keys: [{ kid: 'k1', kty: 'EC', alg: 'ES256' }] }),
    }
    const out = buildOidcRoutes({
      config: { issuer: 'https://app.test' },
      transport,
    })
    expect(out.discovery.issuer).toBe('https://app.test')
    expect(out.jwks.keys).toHaveLength(1)
    expect(out.jwks.keys[0]!.kid).toBe('k1')
  })
})

describe('fetchOidcDiscovery - RP-side cache', () => {
  beforeEach(() => {
    flushOidcDiscoveryCache()
    configureOidcDiscoveryCache({ ttlMs: 60_000, capacity: 4 })
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
    const a = await fetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    const b = await fetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
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
    await expect(fetchOidcDiscovery('https://legit.test', { fetch: fakeFetch })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })

  it('refuses non-HTTPS issuer unless allowHttp is set', async () => {
    await expect(fetchOidcDiscovery('http://idp.test', { fetch: vi.fn() as never })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
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
    await fetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })
    await fetchOidcDiscovery('https://idp.test', { fetch: fakeFetch, bypassCache: true })
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
    await expect(fetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
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
    await expect(fetchOidcDiscovery('https://idp.test', { fetch: fakeFetch })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })
})
