/**
 * The wrapper against a real `@node-saml/node-saml` client, each message signed with a key the test holds.
 * Every other SAML suite fakes the client, and the fakes were shaped by what the wrapper read: node-saml
 * puts no `ID` or `authnContext` on a sign-in profile, copies every attribute onto its top level, and
 * builds a LogoutResponse asynchronously.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto'
import { deflateRawSync, inflateRawSync } from 'node:zlib'
import { SAML } from '@node-saml/node-saml'
import { signXml } from '@node-saml/node-saml/lib/xml'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { MemoryLimiter } from '~/limiters/memory'
import { type Saml, saml, samlSloController } from '../index'

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 })
const IDP_KEY = keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
const IDP_CERT = keys.publicKey.export({ format: 'pem', type: 'spki' }).toString()
const ACS = 'https://sp.test/acs'
const PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
const MFA = 'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken'
const ASSERTION_NS = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
const PROTOCOL_NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
const NAME_ID = `<saml:NameID Format="${EMAIL_FORMAT}">u@corp.test</saml:NameID>`

function client(): SAML {
  return new SAML({
    callbackUrl: ACS,
    entryPoint: 'https://idp.test/sso',
    idpCert: IDP_CERT,
    issuer: 'sp',
    wantAuthnResponseSigned: false,
  })
}

function at(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString()
}

/** Signs the element named `root`, placing the signature after its Issuer as the schema requires. */
function signed(xml: string, root: string): string {
  return signXml(
    xml,
    `//*[local-name(.)='${root}']`,
    { action: 'after', reference: `//*[local-name(.)='${root}']/*[local-name(.)='Issuer']` },
    { privateKey: IDP_KEY, signatureAlgorithm: 'sha256' },
  )
}

/** A base64 SAMLResponse carrying one signed assertion, as an IdP POSTs it. An array attribute is multi-valued. */
function samlResponse(opts: {
  id: string
  classRef: string
  attributes?: Record<string, string | string[]>
  nameId?: string
  sessionIndex?: string
}): string {
  const attributes = Object.entries(opts.attributes ?? {})
    .map(
      ([name, value]) =>
        `<saml:Attribute Name="${name}">${[value]
          .flat()
          .map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`)
          .join('')}</saml:Attribute>`,
    )
    .join('')
  const sessionIndex = opts.sessionIndex === undefined ? '' : ` SessionIndex="${opts.sessionIndex}"`
  const assertion = signed(
    `<saml:Assertion ${ASSERTION_NS} ID="${opts.id}" Version="2.0" IssueInstant="${at(0)}">` +
      `<saml:Issuer>https://idp.test</saml:Issuer>` +
      `<saml:Subject>${opts.nameId ?? NAME_ID}<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData NotOnOrAfter="${at(300_000)}" Recipient="${ACS}"/></saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${at(-60_000)}" NotOnOrAfter="${at(300_000)}">` +
      `<saml:AudienceRestriction><saml:Audience>sp</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
      `<saml:AuthnStatement AuthnInstant="${at(0)}"${sessionIndex}><saml:AuthnContext>` +
      `<saml:AuthnContextClassRef>${opts.classRef}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
      (attributes ? `<saml:AttributeStatement>${attributes}</saml:AttributeStatement>` : '') +
      `</saml:Assertion>`,
    'Assertion',
  )
  const response =
    `<samlp:Response ${PROTOCOL_NS} ID="_${randomUUID()}" Version="2.0" IssueInstant="${at(0)}" Destination="${ACS}">` +
    `<saml:Issuer ${ASSERTION_NS}>https://idp.test</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `${assertion}</samlp:Response>`
  return Buffer.from(response).toString('base64')
}

function ctx() {
  const adapter = new MemoryAdapter()
  return {
    baseUrl: 'https://sp.test',
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
    events: new InMemoryEvents(),
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    tenant: {},
  }
}

/** A provider over a real client, with the replay store it requires and what its hooks saw. */
function provider(over: Partial<Saml.Options> = {}) {
  const consumed: string[] = []
  const signIns: Saml.Profile[] = []
  const p = saml({
    allowUnsolicited: true,
    callbackUrl: ACS,
    client: client(),
    onSignIn: async ({ profile }) => {
      signIns.push(profile)
      return { identityId: 'id-1' }
    },
    replayStore: {
      consume: async (id) => {
        if (consumed.includes(id)) return false
        consumed.push(id)
        return true
      },
    },
    ...over,
  })
  return { consumed, provider: p, signIns }
}

describe('sign-in through a real node-saml client', () => {
  it('signs in with the replay store the provider requires, and refuses the same assertion twice', async () => {
    // node-saml sets no `ID` on a sign-in profile, so the replay store refused every sign-in it was given.
    const { consumed, provider: p } = provider()
    const SAMLResponse = samlResponse({ classRef: PASSWORD, id: '_assertion-1' })
    await expect(p.complete(ctx(), { SAMLResponse })).resolves.toMatchObject([{ identityId: 'id-1' }])
    expect(consumed).toEqual(['_assertion-1'])
    await expect(p.complete(ctx(), { SAMLResponse })).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it.each([
    [MFA, 2],
    [PASSWORD, 1],
  ])('the signed AuthnContextClassRef %s decides aal %i', async (classRef, aal) => {
    const { provider: p } = provider()
    const intents = await p.complete(ctx(), { SAMLResponse: samlResponse({ classRef, id: `_${randomUUID()}` }) })
    expect(intents).toMatchObject([{ aal }])
  })

  it('an attribute named authnContext or ID stands in for neither', async () => {
    // node-saml copies attributes onto the profile's top level, which is where both used to be read.
    const { consumed, provider: p } = provider()
    const intents = await p.complete(ctx(), {
      SAMLResponse: samlResponse({ attributes: { ID: 'chosen', authnContext: MFA }, classRef: PASSWORD, id: '_real' }),
    })
    expect(intents).toMatchObject([{ aal: 1 }])
    expect(consumed).toEqual(['_real'])
  })

  it('an attribute named nameIDFormat does not stand in for a NameID that states none', async () => {
    // With the attribute read as the format, an opaque nameID beside someone else's email passed as `persistent`.
    const both = { allowedNameIdFormats: [EMAIL_FORMAT, PERSISTENT] }
    const forged = provider(both)
    await expect(
      forged.provider.complete(ctx(), {
        SAMLResponse: samlResponse({
          attributes: { email: 'victim@corp.test', nameIDFormat: PERSISTENT },
          classRef: PASSWORD,
          id: `_${randomUUID()}`,
          nameId: '<saml:NameID>opaque-1</saml:NameID>',
        }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    expect(forged.signIns).toEqual([])

    const stated = provider(both)
    await stated.provider.complete(ctx(), {
      SAMLResponse: samlResponse({
        attributes: { email: 'u@corp.test' },
        classRef: PASSWORD,
        id: `_${randomUUID()}`,
        nameId: `<saml:NameID Format="${PERSISTENT}">opaque-1</saml:NameID>`,
      }),
    })
    expect(stated.signIns[0]).toMatchObject({ email: 'u@corp.test', nameID: 'opaque-1', nameIDFormat: PERSISTENT })
  })

  it('an assertion with no NameID is refused, whatever attribute is named nameID', async () => {
    const { provider: p, signIns } = provider()
    await expect(
      p.complete(ctx(), {
        SAMLResponse: samlResponse({ attributes: { nameID: 'chosen' }, classRef: PASSWORD, id: '_n', nameId: '' }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    expect(signIns).toEqual([])
  })

  it('the SessionIndex is the AuthnStatement one, never an attribute', async () => {
    const forged = provider()
    await forged.provider.complete(ctx(), {
      SAMLResponse: samlResponse({ attributes: { sessionIndex: 'chosen' }, classRef: PASSWORD, id: '_s1' }),
    })
    expect(forged.signIns[0]?.sessionIndex).toBeUndefined()

    const real = provider()
    await real.provider.complete(ctx(), {
      SAMLResponse: samlResponse({
        attributes: { sessionIndex: 'chosen' },
        classRef: PASSWORD,
        id: '_s2',
        sessionIndex: '_idx-1',
      }),
    })
    expect(real.signIns[0]?.sessionIndex).toBe('_idx-1')
  })

  it('an email sent more than once is refused rather than crashing the check', async () => {
    const twice = provider()
    await expect(
      twice.provider.complete(ctx(), {
        SAMLResponse: samlResponse({
          attributes: { email: ['u@corp.test', 'victim@corp.test'] },
          classRef: PASSWORD,
          id: '_e1',
        }),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    expect(twice.signIns).toEqual([])

    const once = provider()
    await once.provider.complete(ctx(), {
      SAMLResponse: samlResponse({ attributes: { email: 'u@corp.test' }, classRef: PASSWORD, id: '_e2' }),
    })
    expect(once.signIns[0]?.email).toBe('u@corp.test')
  })

  it('allowedAttributes holds at the top level of the profile too', async () => {
    const { provider: p, signIns } = provider({ allowedAttributes: ['roles'] })
    await p.complete(ctx(), {
      SAMLResponse: samlResponse({ attributes: { isAdmin: 'true', roles: 'owner' }, classRef: PASSWORD, id: '_a' }),
    })
    expect(signIns[0]).not.toHaveProperty('isAdmin')
    expect(signIns[0]?.attributes).toEqual({ roles: 'owner' })
  })
})

describe('IdP-initiated logout through a real node-saml client', () => {
  it('answers the LogoutRequest with a Success InResponseTo it, echoing its RelayState', async () => {
    // node-saml's synchronous builder takes a callback, so the call threw; and it was told the logout failed.
    const request = signed(
      `<samlp:LogoutRequest ${PROTOCOL_NS} ${ASSERTION_NS} ID="_logout-1" Version="2.0" IssueInstant="${at(0)}" NotOnOrAfter="${at(300_000)}">` +
        `<saml:Issuer>https://idp.test</saml:Issuer>${NAME_ID}</samlp:LogoutRequest>`,
      'LogoutRequest',
    )
    const slo = samlSloController({ client: client() })
    const out = await slo.completeIdp({ RelayState: 'rs-1', SAMLRequest: Buffer.from(request).toString('base64') })

    expect(out.nameID).toBe('u@corp.test')
    const url = new URL(out.redirectUrl)
    expect(url.searchParams.get('RelayState')).toBe('rs-1')
    const xml = inflateRawSync(Buffer.from(url.searchParams.get('SAMLResponse') ?? '', 'base64')).toString()
    expect(xml).toContain('InResponseTo="_logout-1"')
    expect(xml).toContain('urn:oasis:names:tc:SAML:2.0:status:Success')
  })
})

describe('Redirect-binding logout through a real node-saml client', () => {
  /** The IdP's side, signing Redirect-binding messages with the key the SP's client trusts. */
  const idp = new SAML({
    callbackUrl: ACS,
    entryPoint: 'https://sp.test/slo',
    idpCert: IDP_CERT,
    issuer: 'https://idp.test',
    logoutUrl: 'https://sp.test/slo',
    privateKey: IDP_KEY,
  })
  const user = { issuer: 'https://idp.test', nameID: 'attacker@corp.test', nameIDFormat: EMAIL_FORMAT }
  const rawQuery = (url: string): string => new URL(url).search.slice(1)

  /** A LogoutRequest naming `nameID`, deflated and encoded as the Redirect binding carries it, signed by nobody. */
  function unsignedRequest(nameID: string): string {
    const xml =
      `<samlp:LogoutRequest ${PROTOCOL_NS} ${ASSERTION_NS} ID="_${randomUUID()}" Version="2.0" IssueInstant="${at(0)}" NotOnOrAfter="${at(300_000)}">` +
      `<saml:Issuer>https://idp.test</saml:Issuer><saml:NameID>${nameID}</saml:NameID></samlp:LogoutRequest>`
    return encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString('base64'))
  }

  it('an IdP LogoutRequest is answered only when the IdP signed it', async () => {
    // node-saml checks a Redirect signature only when one is present, so anyone could log out any nameID.
    const slo = samlSloController({ client: client() })
    await expect(
      slo.completeIdp({ originalQuery: `SAMLRequest=${unsignedRequest('victim@corp.test')}` }),
    ).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    const signed = rawQuery(await idp.getLogoutUrlAsync(user, 'rs', {}))
    await expect(slo.completeIdp({ originalQuery: signed })).resolves.toMatchObject({ nameID: 'attacker@corp.test' })
  })

  it('a second SAMLRequest appended to a signed query is refused, not decoded', async () => {
    const signed = rawQuery(await idp.getLogoutUrlAsync(user, 'rs', {}))
    const slo = samlSloController({ client: client() })
    await expect(
      slo.completeIdp({ originalQuery: `${signed}&SAMLRequest=${unsignedRequest('victim@corp.test')}` }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('an IdP LogoutResponse completes only when the IdP signed it', async () => {
    const slo = samlSloController({ client: client() })
    const signed = rawQuery(await idp.getLogoutResponseUrlAsync({ ...user, ID: '_sp-req-1' }, 'rs', {}, true))
    await expect(slo.completeSp({ originalQuery: signed })).resolves.toBeUndefined()
    const unsigned = signed
      .split('&')
      .filter((t) => !t.startsWith('Signature=') && !t.startsWith('SigAlg='))
      .join('&')
    await expect(slo.completeSp({ originalQuery: unsigned })).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })
})
