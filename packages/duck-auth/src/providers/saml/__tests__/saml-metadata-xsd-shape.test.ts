/**
 * Structural conformance tests for the fallback SAML SP metadata XML
 * (the path used when @node-saml/node-saml is not installed).
 *
 * We don't ship a full XSD validator (would need libxmljs2 / xmldsig as
 * a dev dep). Instead we assert the OASIS SAML 2.0 Metadata required
 * elements + attribute shapes that real IdPs (Okta, Azure AD, ADFS,
 * Auth0, Keycloak) check before they will accept an SP.
 *
 * Sources:
 *   - OASIS SAML 2.0 Metadata XSD: https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd
 *   - SAML 2.0 Core - URI bindings (urn:oasis:names:tc:SAML:2.0:bindings:*)
 *   - Real-IdP heuristics: Okta + Entra ID importers
 */

import { describe, expect, it } from 'vitest'
import { authBuildSpMetadata } from '../index'

const VALID_BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
const VALID_BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'

const VALID_NAMEID_FORMATS = [
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
]

function buildBasicMetadata(
  overrides: Partial<{ entityId: string; acsUrl: string; sloUrl: string; signingCert: string }> = {},
) {
  return authBuildSpMetadata({
    metadata: {
      entityId: overrides.entityId ?? 'https://app.example.com',
      acsUrl: overrides.acsUrl ?? 'https://app.example.com/auth/saml/callback',
      ...(overrides.sloUrl !== undefined && { sloUrl: overrides.sloUrl }),
      ...(overrides.signingCert !== undefined && { signingCert: overrides.signingCert }),
    },
  })
}

describe('SAML 2.0 metadata XML - XML well-formedness', () => {
  it('starts with the XML declaration (xml:1.0)', () => {
    const xml = buildBasicMetadata()
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true)
  })

  it('has a balanced opening + closing EntityDescriptor element', () => {
    const xml = buildBasicMetadata()
    expect(xml).toMatch(/<md:EntityDescriptor[\s>]/)
    expect(xml).toContain('</md:EntityDescriptor>')
  })

  it('declares the md namespace at the root element', () => {
    const xml = buildBasicMetadata()
    expect(xml).toContain('xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"')
  })
})

describe('SAML 2.0 metadata XSD §2.4 - required EntityDescriptor attributes', () => {
  it('EntityDescriptor has entityID attribute (REQUIRED)', () => {
    const xml = buildBasicMetadata({ entityId: 'https://app.example.com' })
    expect(xml).toMatch(/entityID="https:\/\/app\.example\.com"/)
  })

  it('contains exactly one SPSSODescriptor (REQUIRED for SPs)', () => {
    const xml = buildBasicMetadata()
    const openCount = (xml.match(/<md:SPSSODescriptor/g) ?? []).length
    expect(openCount).toBe(1)
  })

  it('SPSSODescriptor advertises SAML 2.0 protocolSupportEnumeration', () => {
    const xml = buildBasicMetadata()
    expect(xml).toContain('protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"')
  })
})

describe('SAML 2.0 metadata XSD §2.4 - AssertionConsumerService', () => {
  it('declares at least one ACS (REQUIRED)', () => {
    const xml = buildBasicMetadata()
    expect(xml).toMatch(/<md:AssertionConsumerService[\s>]/)
  })

  it('ACS Binding attribute references the HTTP-POST URN', () => {
    const xml = buildBasicMetadata()
    expect(xml).toContain(`Binding="${VALID_BINDING_HTTP_POST}"`)
  })

  it('ACS Location is the configured acsUrl', () => {
    const xml = buildBasicMetadata({ acsUrl: 'https://app.example.com/saml-cb' })
    expect(xml).toContain('Location="https://app.example.com/saml-cb"')
  })

  it('ACS has isDefault + index attributes (Okta + Entra require)', () => {
    const xml = buildBasicMetadata()
    expect(xml).toContain('isDefault="true"')
    expect(xml).toContain('index="0"')
  })
})

describe('SAML 2.0 metadata XSD §2.4 - NameIDFormat', () => {
  it('declares a NameIDFormat element (Okta requires)', () => {
    const xml = buildBasicMetadata()
    expect(xml).toMatch(/<md:NameIDFormat[\s>]/)
  })

  it('default NameIDFormat is in the registered OASIS set', () => {
    const xml = buildBasicMetadata()
    const match = xml.match(/<md:NameIDFormat[^>]*>([^<]+)<\/md:NameIDFormat>/)
    expect(match).not.toBeNull()
    if (match) expect(VALID_NAMEID_FORMATS).toContain(match[1])
  })
})

describe('SAML 2.0 metadata XSD §2.4 - SingleLogoutService', () => {
  it('omits SingleLogoutService when sloUrl is not configured', () => {
    const xml = buildBasicMetadata()
    expect(xml).not.toContain('<md:SingleLogoutService')
  })

  it('includes SingleLogoutService when sloUrl is configured', () => {
    const xml = buildBasicMetadata({ sloUrl: 'https://app.example.com/saml-slo' })
    expect(xml).toContain('<md:SingleLogoutService')
  })

  it('SLO Binding is HTTP-Redirect (most common)', () => {
    const xml = buildBasicMetadata({ sloUrl: 'https://app.example.com/saml-slo' })
    expect(xml).toContain(`Binding="${VALID_BINDING_HTTP_REDIRECT}"`)
  })

  it('SLO Location matches sloUrl', () => {
    const xml = buildBasicMetadata({ sloUrl: 'https://app.example.com/saml-slo' })
    expect(xml).toContain('Location="https://app.example.com/saml-slo"')
  })
})

describe('SAML 2.0 metadata XSD §2.4 - KeyDescriptor', () => {
  it('omits KeyDescriptor when no signingCert provided', () => {
    const xml = buildBasicMetadata()
    expect(xml).not.toContain('<md:KeyDescriptor')
  })

  it('emits KeyDescriptor use="signing" when signingCert provided', () => {
    const xml = buildBasicMetadata({ signingCert: 'AAA-cert-bytes' })
    expect(xml).toContain('<md:KeyDescriptor use="signing">')
  })

  it('KeyDescriptor declares ds:KeyInfo namespace', () => {
    const xml = buildBasicMetadata({ signingCert: 'AAA-cert-bytes' })
    expect(xml).toContain('xmlns:ds="http://www.w3.org/2000/09/xmldsig#"')
  })

  it('KeyDescriptor includes the cert under X509Certificate', () => {
    const xml = buildBasicMetadata({ signingCert: 'AAA-cert-bytes' })
    expect(xml).toContain('<ds:X509Certificate>AAA-cert-bytes</ds:X509Certificate>')
  })
})

describe('XML injection defense (CVE-2017-11427 class)', () => {
  it('escapes < in entityId', () => {
    const xml = buildBasicMetadata({ entityId: 'https://app/<evil>' })
    expect(xml).toContain('&lt;evil&gt;')
    expect(xml).not.toContain('<evil>')
  })

  it('escapes " in acsUrl', () => {
    const xml = buildBasicMetadata({ acsUrl: 'https://app/cb?q="bad"' })
    expect(xml).toContain('&quot;')
  })

  it('escapes & in URLs', () => {
    const xml = buildBasicMetadata({ acsUrl: 'https://app/cb?a=1&b=2' })
    expect(xml).toContain('&amp;b=2')
  })

  it('escapes embedded XML tags in cert (defense vs forged ds:Signature injection)', () => {
    const xml = buildBasicMetadata({ signingCert: '</ds:X509Certificate><ds:X509Certificate>EVIL' })
    expect(xml).not.toContain('><ds:X509Certificate>EVIL')
    expect(xml).toContain('&lt;/ds:X509Certificate&gt;')
  })
})

describe('IdP heuristic compatibility', () => {
  it('Okta: AuthnRequestsSigned attribute is set (Okta importer requires)', () => {
    const xml = buildBasicMetadata()
    expect(xml).toContain('AuthnRequestsSigned="true"')
  })

  it('Okta: WantAssertionsSigned defaults to true', () => {
    const xml = buildBasicMetadata()
    expect(xml).toContain('WantAssertionsSigned="true"')
  })

  it('Entra ID: emits md namespace prefix consistently (no default-namespace mix)', () => {
    const xml = buildBasicMetadata()
    // Entra ID's importer rejects metadata that mixes default + prefixed
    // elements. Assert every SAML-2.0 element uses the md: prefix.
    expect(xml).not.toMatch(/<EntityDescriptor[\s>]/)
    expect(xml).not.toMatch(/<SPSSODescriptor[\s>]/)
    expect(xml).not.toMatch(/<NameIDFormat[\s>]/)
  })

  it('ADFS: entityID is a valid absolute URL', () => {
    const xml = buildBasicMetadata({ entityId: 'https://app.example.com' })
    const match = xml.match(/entityID="([^"]+)"/)
    expect(match).not.toBeNull()
    const entityId = match?.[1]
    if (typeof entityId === 'string') expect(() => new URL(entityId)).not.toThrow()
  })
})

describe('Multiple-call determinism', () => {
  it('two calls with identical input produce identical XML', () => {
    const a = buildBasicMetadata({ entityId: 'https://app/sp', acsUrl: 'https://app/cb' })
    const b = buildBasicMetadata({ entityId: 'https://app/sp', acsUrl: 'https://app/cb' })
    expect(a).toBe(b)
  })
})
