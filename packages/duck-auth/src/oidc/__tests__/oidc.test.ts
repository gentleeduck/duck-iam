/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { describe, expect, it } from 'vitest'
import { buildOidcDiscovery, buildOidcRoutes } from '../index'

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
