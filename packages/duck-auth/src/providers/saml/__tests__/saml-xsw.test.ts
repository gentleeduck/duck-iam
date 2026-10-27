/**
 * XML Signature Wrapping against the real `@node-saml/node-saml` client: a validly signed assertion carried
 * somewhere the parser might not look, beside a forged one it might. Ported from better-auth's
 * `packages/sso/src/saml/assertions.test.ts`, which counts assertions itself because its stack does not.
 * We delegate signature and assertion selection to node-saml, so these cases are what makes that delegation
 * evidence rather than an assumption. 5.1.0 refuses a second top-level assertion and a forged wrapper
 * holding the signed one, and ignores an assertion buried anywhere else - so the subject that lands is
 * always the signed one. Each case pins which of the two it is, since a change in either direction is worth
 * hearing about.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto'
import { SAML } from '@node-saml/node-saml'
import { signXml } from '@node-saml/node-saml/lib/xml'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { MemoryLimiter } from '~/limiters/memory'
import { saml } from '../index'

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 })
const IDP_KEY = keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
const IDP_CERT = keys.publicKey.export({ format: 'pem', type: 'spki' }).toString()
const ACS = 'https://sp.test/acs'
const VICTIM = 'u@corp.test'
const ATTACKER = 'attacker@evil.test'
const PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
const ASSERTION_NS = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
const PROTOCOL_NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

function at(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString()
}

/** One assertion body. Signed only when asked: the forged copies are the point. */
function assertion(nameId: string, id: string): string {
  return (
    `<saml:Assertion ${ASSERTION_NS} ID="${id}" Version="2.0" IssueInstant="${at(0)}">` +
    `<saml:Issuer>https://idp.test</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="${EMAIL_FORMAT}">${nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${at(300_000)}" Recipient="${ACS}"/>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${at(-60_000)}" NotOnOrAfter="${at(300_000)}">` +
    `<saml:AudienceRestriction><saml:Audience>sp</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${at(0)}"><saml:AuthnContext>` +
    `<saml:AuthnContextClassRef>${PASSWORD}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `</saml:Assertion>`
  )
}

function signed(xml: string): string {
  return signXml(
    xml,
    "//*[local-name(.)='Assertion']",
    { action: 'after', reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']" },
    { privateKey: IDP_KEY, signatureAlgorithm: 'sha256' },
  )
}

/** The victim's assertion, signed, plus whatever the attacker added around it. */
function response(body: (signedAssertion: string) => string): string {
  const legit = signed(assertion(VICTIM, `_legit-${randomUUID()}`))
  const xml =
    `<samlp:Response ${PROTOCOL_NS} ID="_${randomUUID()}" Version="2.0" IssueInstant="${at(0)}" Destination="${ACS}">` +
    `<saml:Issuer ${ASSERTION_NS}>https://idp.test</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    body(legit) +
    `</samlp:Response>`
  return Buffer.from(xml).toString('base64')
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

/** Reports the nameID it was given, so a case can tell a refusal from a sign-in as the wrong subject. */
function provider(seen: string[]) {
  return saml({
    allowUnsolicited: true,
    callbackUrl: ACS,
    client: new SAML({
      callbackUrl: ACS,
      entryPoint: 'https://idp.test/sso',
      idpCert: IDP_CERT,
      issuer: 'sp',
      wantAuthnResponseSigned: false,
    }),
    onSignIn: async ({ profile }) => {
      seen.push(profile.nameID)
      return { identityId: 'id-1' }
    },
    replayStore: { consume: async () => true },
  })
}

async function attempt(xml: string): Promise<{ signedInAs: string[]; refused: boolean }> {
  const seen: string[] = []
  const refused = await provider(seen)
    .complete(ctx(), { SAMLResponse: xml })
    .then(() => false)
    .catch(() => true)
  return { refused, signedInAs: seen }
}

describe('a forged assertion carried beside a signed one', () => {
  it('signs in as the signed subject when nothing is injected, so the harness is live', async () => {
    const out = await attempt(response((legit) => legit))
    expect(out).toEqual({ refused: false, signedInAs: [VICTIM] })
  })

  it('ignores an assertion injected into samlp:Extensions', async () => {
    const out = await attempt(
      response((legit) => `<samlp:Extensions>${assertion(ATTACKER, 'injected')}</samlp:Extensions>${legit}`),
    )
    expect(out).toEqual({ refused: false, signedInAs: [VICTIM] })
  })

  it('ignores an assertion wrapped in an arbitrary element', async () => {
    const out = await attempt(response((legit) => `<Wrapper>${assertion(ATTACKER, 'wrapped')}</Wrapper>${legit}`))
    expect(out).toEqual({ refused: false, signedInAs: [VICTIM] })
  })

  it('ignores a deeply nested injected assertion', async () => {
    const out = await attempt(
      response((legit) => `<Level1><Level2><Level3>${assertion(ATTACKER, 'deep')}</Level3></Level2></Level1>${legit}`),
    )
    expect(out).toEqual({ refused: false, signedInAs: [VICTIM] })
  })

  it('refuses a second top-level assertion outright', async () => {
    const out = await attempt(response((legit) => `${assertion(ATTACKER, 'sibling')}${legit}`))
    expect(out).toEqual({ refused: true, signedInAs: [] })
  })

  it('refuses a forged assertion holding the signed one in its Advice', async () => {
    // The wrapping attack proper: the signature still resolves over the inner assertion it covers, while a
    // parser reading the outermost one sees the attacker's subject.
    const out = await attempt(
      response(
        (legit) =>
          `<saml:Assertion ${ASSERTION_NS} ID="outer" Version="2.0" IssueInstant="${at(0)}">` +
          `<saml:Issuer>https://idp.test</saml:Issuer>` +
          `<saml:Subject><saml:NameID Format="${EMAIL_FORMAT}">${ATTACKER}</saml:NameID>` +
          `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
          `<saml:SubjectConfirmationData NotOnOrAfter="${at(300_000)}" Recipient="${ACS}"/>` +
          `</saml:SubjectConfirmation></saml:Subject>` +
          `<saml:Conditions NotBefore="${at(-60_000)}" NotOnOrAfter="${at(300_000)}">` +
          `<saml:AudienceRestriction><saml:Audience>sp</saml:Audience></saml:AudienceRestriction>` +
          `</saml:Conditions>` +
          `<saml:Advice>${legit}</saml:Advice>` +
          `<saml:AuthnStatement AuthnInstant="${at(0)}"><saml:AuthnContext>` +
          `<saml:AuthnContextClassRef>${PASSWORD}</saml:AuthnContextClassRef>` +
          `</saml:AuthnContext></saml:AuthnStatement>` +
          `</saml:Assertion>`,
      ),
    )
    expect(out).toEqual({ refused: true, signedInAs: [] })
  })
})
