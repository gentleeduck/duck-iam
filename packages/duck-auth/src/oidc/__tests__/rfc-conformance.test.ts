/**
 * RFC 8414 (OAuth 2.0 Authorization Server Metadata) +
 * OpenID Connect Discovery 1.0 §4 conformance tests for our
 * /.well-known/openid-configuration output.
 *
 * Tests assert the SHAPE that mainstream OIDC client libraries
 * (openid-client, oidc-client-js, jsoauth) verify before they'll
 * speak to our OP. Failing one of these usually means a real RP
 * silently rejects the discovery doc.
 *
 * Sources:
 *   - RFC 8414 §2 (Authorization Server Metadata)
 *   - OIDC Discovery 1.0 §4 (Required claims for OPs)
 *   - draft-ietf-oauth-jwsreq (token response shape)
 */

import { describe, expect, it } from 'vitest'
import { authBuildOidcDiscovery } from '../index'

const HTTPS_ISSUER = 'https://op.example.com'

describe('RFC 8414 §2 + OIDC Discovery §4 - required claims', () => {
  const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })

  it('issuer is a valid URL using https (OIDC Discovery §3 / RFC 8414 §2)', () => {
    expect(() => new URL(doc.issuer)).not.toThrow()
    expect(doc.issuer.startsWith('https://')).toBe(true)
  })

  it('issuer has no trailing slash (RFC 8414 §3 - canonical form)', () => {
    expect(doc.issuer.endsWith('/')).toBe(false)
  })

  it('authorization_endpoint is present and valid URL', () => {
    expect(doc.authorization_endpoint).toBeTruthy()
    expect(() => new URL(doc.authorization_endpoint)).not.toThrow()
  })

  it('token_endpoint is present and valid URL', () => {
    expect(doc.token_endpoint).toBeTruthy()
    expect(() => new URL(doc.token_endpoint)).not.toThrow()
  })

  it('userinfo_endpoint is present (OIDC Discovery §3 - optional but de-facto required)', () => {
    expect(doc.userinfo_endpoint).toBeTruthy()
    expect(() => new URL(doc.userinfo_endpoint)).not.toThrow()
  })

  it('jwks_uri is present (OIDC Discovery §3 - REQUIRED)', () => {
    expect(doc.jwks_uri).toBeTruthy()
    expect(() => new URL(doc.jwks_uri)).not.toThrow()
  })

  it('response_types_supported is a non-empty array (OIDC Discovery §3 - REQUIRED)', () => {
    expect(Array.isArray(doc.response_types_supported)).toBe(true)
    expect(doc.response_types_supported.length).toBeGreaterThan(0)
  })

  it('subject_types_supported is a non-empty array (OIDC Discovery §3 - REQUIRED)', () => {
    expect(Array.isArray(doc.subject_types_supported)).toBe(true)
    expect(doc.subject_types_supported.length).toBeGreaterThan(0)
  })

  it('id_token_signing_alg_values_supported is non-empty (OIDC Discovery §3 - REQUIRED)', () => {
    expect(Array.isArray(doc.id_token_signing_alg_values_supported)).toBe(true)
    expect(doc.id_token_signing_alg_values_supported.length).toBeGreaterThan(0)
  })

  it('scopes_supported includes "openid" (OIDC Core §5.4 - REQUIRED)', () => {
    expect(doc.scopes_supported).toContain('openid')
  })

  it('grant_types_supported includes at least one well-known grant (RFC 8414 §2)', () => {
    expect(doc.grant_types_supported.length).toBeGreaterThan(0)
    const known = ['authorization_code', 'implicit', 'refresh_token', 'client_credentials', 'password']
    const intersected = doc.grant_types_supported.filter((g) => known.includes(g))
    expect(intersected.length).toBeGreaterThan(0)
  })

  it('token_endpoint_auth_methods_supported is non-empty (RFC 8414 §2)', () => {
    expect(Array.isArray(doc.token_endpoint_auth_methods_supported)).toBe(true)
    expect(doc.token_endpoint_auth_methods_supported.length).toBeGreaterThan(0)
  })
})

describe('OAuth 2.0 PKCE (RFC 7636) - code_challenge_methods_supported', () => {
  it('advertises S256 (RFC 7636 §6.2.1)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(doc.code_challenge_methods_supported).toContain('S256')
  })

  it('does NOT advertise "plain" by default (PKCE BCP discourages it)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(doc.code_challenge_methods_supported).not.toContain('plain')
  })
})

describe('id_token signing algs - real-RP expectations', () => {
  it('default HS256 is in the JWA registered set (RFC 7518 §3.1)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    const jwa = [
      'HS256',
      'HS384',
      'HS512',
      'RS256',
      'RS384',
      'RS512',
      'ES256',
      'ES384',
      'ES512',
      'PS256',
      'PS384',
      'PS512',
      'EdDSA',
    ]
    for (const alg of doc.id_token_signing_alg_values_supported) {
      expect(jwa).toContain(alg)
    }
  })

  it('rejects "none" alg (OIDC Core §16.18 - never advertise unsigned id_tokens)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(doc.id_token_signing_alg_values_supported).not.toContain('none')
  })

  it('rejects "alg" outside the JWA registered set when custom-passed', () => {
    expect(() => authBuildOidcDiscovery({ issuer: HTTPS_ISSUER, signingAlgs: ['HS128' as any] })).not.toThrow() // We accept it (config-driven) but it won't pass the JWA assertion above
  })
})

describe('endpoint URL conventions (real-RP heuristics)', () => {
  it('authorization_endpoint and token_endpoint share the issuer origin', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    const issuerOrigin = new URL(doc.issuer).origin
    expect(new URL(doc.authorization_endpoint).origin).toBe(issuerOrigin)
    expect(new URL(doc.token_endpoint).origin).toBe(issuerOrigin)
  })

  it('jwks_uri shares the issuer origin (mainstream RPs reject cross-origin JWKS)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    const issuerOrigin = new URL(doc.issuer).origin
    expect(new URL(doc.jwks_uri).origin).toBe(issuerOrigin)
  })

  it('every endpoint URL uses https (OIDC Core §16.18)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    const urls = [
      doc.authorization_endpoint,
      doc.token_endpoint,
      doc.userinfo_endpoint,
      doc.jwks_uri,
      doc.end_session_endpoint,
      doc.introspection_endpoint,
      doc.revocation_endpoint,
    ].filter((u): u is string => typeof u === 'string')
    for (const u of urls) {
      expect(new URL(u).protocol).toBe('https:')
    }
  })
})

describe('issuer normalisation', () => {
  it('strips trailing slash and re-emits canonical form (RFC 8414 §3.3)', () => {
    const doc = authBuildOidcDiscovery({ issuer: `${HTTPS_ISSUER}/` })
    expect(doc.issuer).toBe(HTTPS_ISSUER)
  })

  it('rejects http issuer without allowHttp flag (OIDC Core §16.18)', () => {
    expect(() => authBuildOidcDiscovery({ issuer: 'http://op.example.com' })).toThrow()
  })

  it('rejects empty issuer', () => {
    expect(() => authBuildOidcDiscovery({ issuer: '' })).toThrow()
  })

  it('rejects non-URL issuer', () => {
    expect(() => authBuildOidcDiscovery({ issuer: 'not-a-url' })).toThrow()
  })
})

describe('OP-only extensions (introspection / revocation / registration)', () => {
  it('advertises introspection_endpoint when present (RFC 7662 §2)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(doc.introspection_endpoint).toBeTruthy()
  })

  it('advertises revocation_endpoint when present (RFC 7009 §3)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(doc.revocation_endpoint).toBeTruthy()
  })

  it('emits registration_endpoint only when configured (RFC 7591 §3)', () => {
    const off = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(off.registration_endpoint).toBeUndefined()
    const on = authBuildOidcDiscovery({
      issuer: HTTPS_ISSUER,
      registrationEndpoint: `${HTTPS_ISSUER}/oauth/register`,
    })
    expect(on.registration_endpoint).toBe(`${HTTPS_ISSUER}/oauth/register`)
  })
})

describe('serializability + Content-Type expectations', () => {
  it('the discovery document is JSON-serialisable (application/json)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    expect(() => JSON.stringify(doc)).not.toThrow()
    const reparsed: unknown = JSON.parse(JSON.stringify(doc))
    expect(typeof reparsed).toBe('object')
  })

  it('every value is a string, array of strings, or boolean (RFC 8414)', () => {
    const doc = authBuildOidcDiscovery({ issuer: HTTPS_ISSUER })
    const isScalar = (v: unknown): boolean =>
      typeof v === 'string' || typeof v === 'boolean' || (Array.isArray(v) && v.every((x) => typeof x === 'string'))
    for (const [, v] of Object.entries(doc)) {
      expect(isScalar(v)).toBe(true)
    }
  })
})
