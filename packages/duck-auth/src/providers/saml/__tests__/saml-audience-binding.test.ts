/**
 * What binds an assertion to *this* Service Provider, against a real `@node-saml/node-saml` client. Of the
 * three bindings better-auth's `response-binding.test.ts` checks, 5.1.0 compares only `AudienceRestriction`:
 * `Recipient` and `Destination` are parsed and ignored, which the cases below show by execution.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto'
import { SAML } from '@node-saml/node-saml'
import { signXml } from '@node-saml/node-saml/lib/xml'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { MemoryLimiter } from '~/limiters/memory'
import { type Saml, saml } from '../index'

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 })
const IDP_KEY = keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
const IDP_CERT = keys.publicKey.export({ format: 'pem', type: 'spki' }).toString()
const ACS = 'https://sp.test/acs'
const OTHER_ACS = 'https://other-sp.test/acs'
const PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
const ASSERTION_NS = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
const PROTOCOL_NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

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

/** One signed assertion, as the IdP POSTs it. Each binding is a parameter, so a case can move one alone. */
function samlResponse(
  over: { audience?: string; recipient?: string; destination?: string; id?: string; conditions?: false } = {},
): string {
  const audience = over.audience ?? 'sp'
  const recipient = over.recipient ?? ACS
  const destination = over.destination ?? ACS
  // Omitted before signing: editing a signed assertion would fail on the signature instead.
  const conditions =
    over.conditions === false
      ? ''
      : `<saml:Conditions NotBefore="${at(-60_000)}" NotOnOrAfter="${at(300_000)}">` +
        `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>` +
        `</saml:Conditions>`
  const assertion = signed(
    `<saml:Assertion ${ASSERTION_NS} ID="${over.id ?? `_a-${randomUUID()}`}" Version="2.0" IssueInstant="${at(0)}">` +
      `<saml:Issuer>https://idp.test</saml:Issuer>` +
      `<saml:Subject><saml:NameID Format="${EMAIL_FORMAT}">u@corp.test</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData NotOnOrAfter="${at(300_000)}" Recipient="${recipient}"/>` +
      `</saml:SubjectConfirmation></saml:Subject>` +
      conditions +
      `<saml:AuthnStatement AuthnInstant="${at(0)}"><saml:AuthnContext>` +
      `<saml:AuthnContextClassRef>${PASSWORD}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
      `</saml:Assertion>`,
    'Assertion',
  )
  const response =
    `<samlp:Response ${PROTOCOL_NS} ID="_${randomUUID()}" Version="2.0" IssueInstant="${at(0)}" Destination="${destination}">` +
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

/** `audience` left alone resolves to `issuer`, which is this SP. `false` turns the check off. */
function client(audience?: false): SAML {
  return new SAML({
    callbackUrl: ACS,
    entryPoint: 'https://idp.test/sso',
    idpCert: IDP_CERT,
    issuer: 'sp',
    wantAuthnResponseSigned: false,
    ...(audience === false && { audience: false }),
  })
}

function provider(over: Partial<Saml.Options> = {}) {
  return saml({
    allowUnsolicited: true,
    callbackUrl: ACS,
    client: client(),
    onSignIn: async () => ({ identityId: 'id-1' }),
    replayStore: { consume: async () => true },
    ...over,
  })
}

describe('AudienceRestriction is what binds an assertion to this Service Provider', () => {
  it('signs in when the audience is this SP, so the harness is live', async () => {
    await expect(provider().complete(ctx(), { SAMLResponse: samlResponse() })).resolves.toMatchObject([
      { identityId: 'id-1' },
    ])
  })

  it('refuses an assertion minted for another Service Provider', async () => {
    // One IdP signs for many SPs, so a cryptographically perfect assertion for `other-sp` must not land.
    await expect(
      provider().complete(ctx(), { SAMLResponse: samlResponse({ audience: 'other-sp' }) }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('refuses an assertion carrying no AudienceRestriction at all', async () => {
    // An absent restriction must not read as an unrestricted one.
    await expect(
      provider().complete(ctx(), { SAMLResponse: samlResponse({ conditions: false }) }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })
})

describe('the two bindings node-saml parses and never compares', () => {
  it('accepts a bearer Recipient naming another Service Provider', async () => {
    // What node-saml 5.1.0 does, and the reason the audience check must stay on.
    await expect(
      provider().complete(ctx(), { SAMLResponse: samlResponse({ recipient: OTHER_ACS }) }),
    ).resolves.toMatchObject([{ identityId: 'id-1' }])
  })

  it('accepts a response Destination naming another Service Provider', async () => {
    await expect(
      provider().complete(ctx(), { SAMLResponse: samlResponse({ destination: OTHER_ACS }) }),
    ).resolves.toMatchObject([{ identityId: 'id-1' }])
  })
})

describe('a client told to skip the audience check', () => {
  it('signs in on an assertion minted for another Service Provider, every other binding ignored', async () => {
    // Nothing is left: any assertion this IdP ever signed, for any SP, mints a session.
    const sam = new SAML({
      callbackUrl: ACS,
      entryPoint: 'https://idp.test/sso',
      idpCert: IDP_CERT,
      issuer: 'sp',
      wantAuthnResponseSigned: false,
      audience: false,
    })
    const profile = await sam.validatePostResponseAsync({
      SAMLResponse: samlResponse({ audience: 'other-sp', destination: OTHER_ACS, recipient: OTHER_ACS }),
    })
    expect(profile.profile?.nameID).toBe('u@corp.test')
  })

  it('is refused at construction, rather than being discovered at the callback', () => {
    expect(() => provider({ client: client(false) })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('is accepted once the host says so, which is a decision and not a forgotten key', () => {
    expect(() => provider({ allowAnyAudience: true, client: client(false) })).not.toThrow()
  })
})
