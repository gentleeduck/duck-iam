import { describe, expect, it, vi } from 'vitest'
import { buildSpMetadata, SamlProvider, samlSloController } from '../index'

function makeClient(overrides: Partial<SamlProvider.IClient> = {}): SamlProvider.IClient {
  return {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp/sso'),
    validatePostResponseAsync: vi.fn(async () => ({
      profile: { nameID: 'user-1' } as SamlProvider.IProfile,
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
    await expect(slo.beginSp({ nameID: 'u', relayState: 'r' })).rejects.toMatchObject({ code: 'AUTH/MISCONFIGURED' })
  })

  it('rejects empty nameID', async () => {
    const slo = samlSloController({
      client: makeClient({ getLogoutUrlAsync: vi.fn(async () => 'https://idp/slo') }),
    })
    await expect(slo.beginSp({ nameID: '', relayState: 'r' })).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('rejects CR/LF in nameID and relayState', async () => {
    const slo = samlSloController({
      client: makeClient({ getLogoutUrlAsync: vi.fn(async () => 'https://idp/slo') }),
    })
    await expect(slo.beginSp({ nameID: 'a\nb', relayState: 'r' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
    await expect(slo.beginSp({ nameID: 'a', relayState: 'r\r' })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })
})

describe('samlSloController.completeSp', () => {
  it('returns nameID after validating an IdP LogoutResponse', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({
        profile: { nameID: 'u-1' } as SamlProvider.IProfile,
        loggedOut: true,
      })),
    })
    const slo = samlSloController({ client })
    const out = await slo.completeSp({
      query: { SAMLResponse: 'enc', SigAlg: 'sig', Signature: 's' },
      originalQuery: 'SAMLResponse=enc&SigAlg=sig&Signature=s',
    })
    expect(out.nameID).toBe('u-1')
  })

  it('rejects when validateRedirectAsync flags loggedOut=false', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({
        profile: { nameID: 'u' } as SamlProvider.IProfile,
        loggedOut: false,
      })),
    })
    const slo = samlSloController({ client })
    await expect(
      slo.completeSp({ query: { SAMLResponse: 'x' }, originalQuery: 'SAMLResponse=x' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('caps oversize originalQuery', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({ profile: null, loggedOut: true })),
    })
    const slo = samlSloController({ client })
    const huge = 'X'.repeat(2_000_000)
    await expect(slo.completeSp({ query: {}, originalQuery: huge })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })

  it('scrubs internal validation error messages from the response', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => {
        throw new Error('signature did not verify against IdP cert XYZ; offset=12345')
      }),
    })
    const slo = samlSloController({ client })
    await expect(slo.completeSp({ query: {}, originalQuery: 'q=1' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })
})

describe('samlSloController.completeIdp', () => {
  it('handles a Redirect-binding LogoutRequest end to end', async () => {
    const client = makeClient({
      validateRedirectAsync: vi.fn(async () => ({
        profile: { nameID: 'idp-init-user' } as SamlProvider.IProfile,
        loggedOut: true,
      })),
      getLogoutResponseUrl: vi.fn(() => 'https://idp/slo?SAMLResponse=BBB'),
    })
    const slo = samlSloController({ client })
    const out = await slo.completeIdp({
      query: { SAMLRequest: 'enc', Signature: 's' },
      originalQuery: 'SAMLRequest=enc&Signature=s',
    })
    expect(out.nameID).toBe('idp-init-user')
    expect(out.redirectUrl).toContain('SAMLResponse=BBB')
  })

  it('handles a POST-binding LogoutRequest', async () => {
    const client = makeClient({
      validatePostRequestAsync: vi.fn(async () => ({
        profile: { nameID: 'post-bind-user' } as SamlProvider.IProfile,
        loggedOut: true,
      })),
      getLogoutResponseUrl: vi.fn(() => 'https://idp/slo?SAMLResponse=CCC'),
    })
    const slo = samlSloController({ client })
    const out = await slo.completeIdp({ SAMLRequest: '<saml:LogoutRequest/>' })
    expect(out.nameID).toBe('post-bind-user')
  })

  it('rejects when neither query nor SAMLRequest is supplied', async () => {
    const slo = samlSloController({ client: makeClient({ getLogoutResponseUrl: vi.fn(() => '') }) })
    await expect(slo.completeIdp({})).rejects.toMatchObject({ code: 'AUTH/MISCONFIGURED' })
  })

  it('rejects when client lacks getLogoutResponseUrl', async () => {
    const slo = samlSloController({ client: makeClient() })
    await expect(slo.completeIdp({ SAMLRequest: 'x' })).rejects.toMatchObject({ code: 'AUTH/MISCONFIGURED' })
  })

  it('rejects when the validated message is not a logout (loggedOut=false)', async () => {
    const slo = samlSloController({
      client: makeClient({
        validatePostRequestAsync: vi.fn(async () => ({
          profile: { nameID: 'u' } as SamlProvider.IProfile,
          loggedOut: false,
        })),
        getLogoutResponseUrl: vi.fn(() => ''),
      }),
    })
    await expect(slo.completeIdp({ SAMLRequest: '<x/>' })).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })
})
