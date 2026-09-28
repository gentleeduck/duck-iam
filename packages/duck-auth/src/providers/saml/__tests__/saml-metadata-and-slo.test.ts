import { describe, expect, it, vi } from 'vitest'
import { buildSpMetadata, Saml, samlSloController } from '../index'
import { SAML_NAME_ID_MAX } from '../saml.constants'

function makeClient(overrides: Partial<Saml.Client> = {}): Saml.Client {
  return {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp/sso'),
    validatePostResponseAsync: vi.fn(async () => ({
      profile: { nameID: 'user-1' },
      loggedOut: false,
    })),
    ...overrides,
  }
}

describe('buildSpMetadata', () => {
  it('delegates to client.generateServiceProviderMetadata when present', () => {
    const client = makeClient({
      generateServiceProviderMetadata: vi.fn(() => '<md:EntityDescriptor from-client="true"/>'),
    })
    const xml = buildSpMetadata({
      client,
      metadata: { entityId: 'https://app/sp', acsUrl: 'https://app/acs' },
    })
    expect(xml).toBe('<md:EntityDescriptor from-client="true"/>')
  })

  it('falls back to a hand-rolled XML doc when client cannot generate', () => {
    const xml = buildSpMetadata({
      metadata: {
        entityId: 'https://app/sp',
        acsUrl: 'https://app/acs',
        sloUrl: 'https://app/slo',
        displayName: 'Test App',
      },
    })
    expect(xml).toContain('entityID="https://app/sp"')
    expect(xml).toContain('Location="https://app/acs"')
    expect(xml).toContain('Location="https://app/slo"')
    expect(xml).toContain('Test App')
    expect(xml).toContain('NameIDFormat')
    expect(xml).toContain('SPSSODescriptor')
  })

  it('escapes XML special characters in user-supplied fields', () => {
    const xml = buildSpMetadata({
      metadata: {
        entityId: 'https://app/sp?x=<bad>',
        acsUrl: 'https://app/acs?q="evil"&y=1',
      },
    })
    expect(xml).toContain('&lt;bad&gt;')
    expect(xml).toContain('&quot;evil&quot;')
    expect(xml).toContain('&amp;y=1')
    expect(xml).not.toContain('<bad>')
  })

  it('omits SLO service element when sloUrl missing', () => {
    const xml = buildSpMetadata({
      metadata: { entityId: 'https://app/sp', acsUrl: 'https://app/acs' },
    })
    expect(xml).not.toContain('SingleLogoutService')
  })
})

describe('samlSloController.beginSp', () => {
  it('builds a LogoutRequest redirect URL', async () => {
    const client = makeClient({
      getLogoutUrlAsync: vi.fn(async () => 'https://idp/slo?SAMLRequest=AAA'),
    })
    const slo = samlSloController({ client })
    const out = await slo.beginSp({
      nameID: 'user@x.com',
      nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      sessionIndex: 'sess-1',
      relayState: 'r',
    })
    expect(out.redirectUrl).toContain('SAMLRequest=AAA')
    expect(client.getLogoutUrlAsync).toHaveBeenCalledWith(
      expect.objectContaining({ nameID: 'user@x.com', nameIDFormat: expect.any(String), sessionIndex: 'sess-1' }),
      'r',
      {},
    )
  })

  it('rejects when client lacks getLogoutUrlAsync', async () => {
    const slo = samlSloController({ client: makeClient() })
    await expect(slo.beginSp({ nameID: 'u', relayState: 'r' })).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it('refuses an empty or over-long nameID as a bad argument, and accepts one at the cap', async () => {
    const slo = samlSloController({
      client: makeClient({ getLogoutUrlAsync: vi.fn(async () => 'https://idp/slo') }),
    })
    for (const nameID of ['', 'x'.repeat(SAML_NAME_ID_MAX + 1)]) {
      await expect(slo.beginSp({ nameID, relayState: 'r' })).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    }
    await expect(slo.beginSp({ nameID: 'x'.repeat(SAML_NAME_ID_MAX), relayState: 'r' })).resolves.toEqual({
      redirectUrl: 'https://idp/slo',
    })
  })

  it('rejects CR/LF in nameID and relayState', async () => {
    const slo = samlSloController({
      client: makeClient({ getLogoutUrlAsync: vi.fn(async () => 'https://idp/slo') }),
    })
    await expect(slo.beginSp({ nameID: 'a\nb', relayState: 'r' })).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
    })
    await expect(slo.beginSp({ nameID: 'a', relayState: 'r\r' })).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
    })
  })
})

describe('samlSloController.completeSp', () => {
  it('resolves once the IdP LogoutResponse validates, parsed from the raw query alone', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({ profile: null, loggedOut: true })),
    })
    const slo = samlSloController({ client })
    await expect(
      slo.completeSp({ originalQuery: 'SAMLResponse=enc&SigAlg=sig&Signature=s%2B1&other=1' }),
    ).resolves.toBeUndefined()
    expect(client.validateRedirectAsync).toHaveBeenCalledWith(
      { SAMLResponse: 'enc', SigAlg: 'sig', Signature: 's+1' },
      'SAMLResponse=enc&SigAlg=sig&Signature=s%2B1',
    )
  })

  it.each([
    ['unsigned', 'SAMLResponse=enc'],
    ['with no SigAlg', 'SAMLResponse=enc&Signature=s'],
    ['with a second SAMLResponse', 'SAMLResponse=signed&SigAlg=a&Signature=s&SAMLResponse=forged'],
    ['with a second SigAlg', 'SAMLResponse=enc&SigAlg=a&Signature=s&SigAlg=b'],
  ])('refuses a LogoutResponse %s before the client sees it', async (_, originalQuery) => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({ profile: null, loggedOut: true })),
    })
    await expect(samlSloController({ client }).completeSp({ originalQuery })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(client.validateRedirectAsync).not.toHaveBeenCalled()
  })

  it('rejects when validateRedirectAsync flags loggedOut=false', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({
        profile: { nameID: 'u' },
        loggedOut: false,
      })),
    })
    const slo = samlSloController({ client })
    await expect(slo.completeSp({ originalQuery: 'SAMLResponse=x&SigAlg=a&Signature=s' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('caps oversize originalQuery', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({ profile: null, loggedOut: true })),
    })
    const slo = samlSloController({ client })
    const huge = 'X'.repeat(2_000_000)
    await expect(slo.completeSp({ originalQuery: huge })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('scrubs internal validation error messages from the response', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => {
        throw new Error('signature did not verify against IdP cert XYZ; offset=12345')
      }),
    })
    const slo = samlSloController({ client })
    await expect(slo.completeSp({ originalQuery: 'SAMLResponse=x&SigAlg=a&Signature=s' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
      meta: { detail: 'LogoutResponse validation failed' },
    })
    expect(client.validateRedirectAsync).toHaveBeenCalled()
  })
})

describe('samlSloController.completeIdp', () => {
  it('handles a Redirect-binding LogoutRequest, answering it by ID with its own RelayState', async () => {
    const request = { ID: '_req-1', nameID: 'idp-init-user' }
    const client = makeClient({
      getLogoutResponseUrlAsync: vi.fn(async () => 'https://idp/slo?SAMLResponse=BBB'),
      validateRedirectAsync: vi.fn(async () => ({ loggedOut: true, profile: request })),
    })
    const slo = samlSloController({ client })
    const out = await slo.completeIdp({ originalQuery: 'SAMLRequest=enc&RelayState=rs&SigAlg=a&Signature=s' })
    expect(out).toEqual({ nameID: 'idp-init-user', redirectUrl: 'https://idp/slo?SAMLResponse=BBB' })
    expect(client.getLogoutResponseUrlAsync).toHaveBeenCalledWith(request, 'rs', {}, true)
  })

  it.each([
    ['unsigned', 'SAMLRequest=enc&RelayState=rs'],
    ['with a second SAMLRequest', 'SAMLRequest=signed&SigAlg=a&Signature=s&SAMLRequest=forged'],
    ['with a second RelayState', 'SAMLRequest=enc&RelayState=a&SigAlg=a&Signature=s&RelayState=b'],
  ])('refuses a Redirect-binding LogoutRequest %s before the client sees it', async (_, originalQuery) => {
    const client = makeClient({
      getLogoutResponseUrlAsync: vi.fn(async () => ''),
      validateRedirectAsync: vi.fn(async () => ({ loggedOut: true, profile: { ID: '_r', nameID: 'victim' } })),
    })
    await expect(samlSloController({ client }).completeIdp({ originalQuery })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(client.validateRedirectAsync).not.toHaveBeenCalled()
  })

  it('handles a POST-binding LogoutRequest, echoing the RelayState posted beside it', async () => {
    const request = { ID: '_req-2', nameID: 'post-bind-user' }
    const client = makeClient({
      getLogoutResponseUrlAsync: vi.fn(async () => 'https://idp/slo?SAMLResponse=CCC'),
      validatePostRequestAsync: vi.fn(async () => ({ loggedOut: true, profile: request })),
    })
    const slo = samlSloController({ client })
    const out = await slo.completeIdp({ RelayState: 'posted', SAMLRequest: '<saml:LogoutRequest/>' })
    expect(out.nameID).toBe('post-bind-user')
    expect(client.getLogoutResponseUrlAsync).toHaveBeenCalledWith(request, 'posted', {}, true)
  })

  it('rejects when neither query nor SAMLRequest is supplied, as a bad request', async () => {
    const slo = samlSloController({ client: makeClient({ getLogoutResponseUrlAsync: vi.fn(async () => '') }) })
    await expect(slo.completeIdp({})).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
  })

  it('rejects when client lacks getLogoutResponseUrlAsync', async () => {
    const slo = samlSloController({ client: makeClient() })
    await expect(slo.completeIdp({ SAMLRequest: 'x' })).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it.each([
    ['a sign-in assertion', { loggedOut: false, profile: { nameID: 'u' } }],
    ['a logout carrying no request', { loggedOut: true, profile: null }],
  ])('rejects %s', async (_, validated) => {
    const slo = samlSloController({
      client: makeClient({
        getLogoutResponseUrlAsync: vi.fn(async () => ''),
        validatePostRequestAsync: vi.fn(async () => validated),
      }),
    })
    await expect(slo.completeIdp({ SAMLRequest: '<x/>' })).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })
})
