/**
 * A SAML sign-in is a browser POSTing an assertion the relying party did not
 * ask for over a channel the relying party does not control, so the provider's
 * job is deciding which assertions belong to which request. The existing suites
 * cover the input caps, the nameID guard, and the error redaction.
 *
 * These cover the binding: what ties a response to the request that started it,
 * what the assurance level of the resulting session is based on, and which
 * configured options actually take part in the decision.
 *
 * Sources: SAML 2.0 core section 3.2.2 (InResponseTo), the Web Browser SSO
 * profile section 4.1.4.3 on validating Destination and Recipient, OWASP's SAML
 * security cheat sheet on assertion replay and login CSRF, and NIST SP 800-63B
 * section 4 on what an AAL 2 claim requires.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { type Saml, saml } from '../index'

interface MyProfile extends Identities.ProfileMetadataBase {}

function ctxFor(adapter: MemoryAdapter<MyProfile>, over: { events?: InMemoryEvents; tenantId?: string } = {}) {
  return {
    baseUrl: 'https://app.test',
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
    events: over.events ?? new InMemoryEvents(),
    limiter: new MemoryLimiter({ max: 3, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    tenant: over.tenantId !== undefined ? { tenantId: over.tenantId } : {},
  }
}

function makeClient(over: Partial<Saml.Client> = {}): Saml.Client {
  return {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp.example/sso?SAMLRequest=AAA'),
    validatePostResponseAsync: vi.fn(async () => ({
      loggedOut: false,
      profile: { email: 'user@x.com', nameID: 'sso-user-1' } as Saml.Profile,
    })),
    ...over,
  }
}

/** A provider plus the calls its onSignIn hook received. */
function makeProvider(over: Partial<Saml.Options<MyProfile>> = {}, client = makeClient()) {
  const signIns: Array<{ profile: Saml.Profile; tenantId?: string }> = []
  const provider = saml<MyProfile>({
    callbackUrl: 'https://app.test/auth/saml/acs',
    client,
    onSignIn: async (input) => {
      signIns.push(input)
      return { identityId: `id-for-${input.profile.nameID}` }
    },
    ...over,
  })
  return { client, provider, signIns }
}

describe('what ties a response to the request that started it', () => {
  it('begin hands the relay state and the host to the client and redirects', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { client, provider } = makeProvider()
    const intents = await provider.begin(ctxFor(adapter), { host: 'app.test', relayState: 'state-abc' })

    expect(intents).toEqual([{ status: 302, type: 'redirect', url: 'https://idp.example/sso?SAMLRequest=AAA' }])
    expect(client.getAuthorizeUrlAsync).toHaveBeenCalledWith('state-abc', 'app.test', {})
  })

  it('FINDING: complete takes no relay state, so the value begin calls a CSRF guard is never checked', async () => {
    // `BeginInput.relayState` is documented as "Caller-supplied relay state
    // (CSRF guard); echoed back by IdP". `CompleteInput` has one field, the
    // SAMLResponse, so nothing in this provider ever compares the echoed value
    // against the one it sent. The guard exists on the way out and has no
    // counterpart on the way back.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider()
    await provider.begin(ctxFor(adapter), { host: 'app.test', relayState: 'state-abc' })

    // No relay state supplied, and the sign-in completes anyway.
    const intents = await provider.complete(ctxFor(adapter), { SAMLResponse: 'base64-xml' })
    expect(intents[0]).toMatchObject({ type: 'startSession' })
    expect(signIns).toHaveLength(1)
  })

  it('FINDING: complete succeeds with no preceding begin at all', async () => {
    // Unsolicited responses are a supported flow, so this is by design, but it
    // means every response is accepted on its own merits. An assertion an
    // attacker obtained for their own account, POSTed into a victim's browser,
    // is indistinguishable here from one the victim asked for. That is SAML
    // login CSRF, and the defence is exactly the relay state binding above.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider()
    const intents = await provider.complete(ctxFor(adapter), { SAMLResponse: 'unsolicited' })
    expect(intents[0]).toMatchObject({ identityId: 'id-for-sso-user-1', type: 'startSession' })
  })

  it('FINDING: the same response body can be replayed indefinitely', async () => {
    // Replay protection lives in the node-saml client's InResponseTo cache,
    // which this wrapper neither configures nor requires. With a client that
    // does not have one, the provider mints a fresh session for every repeat of
    // one captured POST body.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider()
    for (let i = 0; i < 5; i++) await provider.complete(ctxFor(adapter), { SAMLResponse: 'same-body' })
    expect(signIns).toHaveLength(5)
  })

  it('FINDING: callbackUrl is required at construction and then never read', async () => {
    // It is documented as "Must exactly match the AssertionConsumerService URL
    // registered with the IdP", which reads as a check. It is a presence test:
    // nothing compares it against the response's Destination or the assertion's
    // Recipient, so a response minted for a different ACS is accepted here.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider({ callbackUrl: 'https://completely-different.example/acs' })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).resolves.toBeDefined()
  })

  it('FINDING: nothing binds an assertion to the tenant it is being consumed under', async () => {
    // The tenant from the context is passed to `onSignIn` as context, not as a
    // constraint. One provider instance serving several tenants accepts the same
    // assertion under any of them, and which tenant a session lands in is decided
    // by the request rather than by the assertion.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider()
    await provider.complete(ctxFor(adapter, { tenantId: 'tenant-a' }), { SAMLResponse: 'x' })
    await provider.complete(ctxFor(adapter, { tenantId: 'tenant-b' }), { SAMLResponse: 'x' })

    expect(signIns.map((s) => s.tenantId)).toEqual(['tenant-a', 'tenant-b'])
  })
})

describe('the assurance level the session is given', () => {
  it('FINDING: every SAML sign-in is stamped aal 2 regardless of what the IdP did', async () => {
    // The level is a literal in the intent. The response's AuthnContextClassRef,
    // which is where an IdP states whether it actually performed a second
    // factor, is not inspected and is not even carried on `Saml.Profile`. A
    // password-only IdP therefore produces a session that satisfies every
    // step-up requirement in this library.
    const adapter = new MemoryAdapter<MyProfile>()
    const client = makeClient({
      validatePostResponseAsync: vi.fn(async () => ({
        loggedOut: false,
        profile: {
          attributes: { AuthnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' },
          nameID: 'sso-user-1',
        } as Saml.Profile,
      })),
    })
    const { provider } = makeProvider({}, client)

    expect((await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' }))[0]).toMatchObject({ aal: 2 })
  })

  it('FINDING: the factor is recorded as oauth, so audit cannot tell SAML from an oauth sign-in', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider()
    const [intent] = await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(intent).toMatchObject({ factors: [{ method: 'oauth' }] })
  })

  it('reports its kind as oauth for the same reason', () => {
    expect(makeProvider().provider.kind).toBe('oauth')
  })

  it('takes the configured provider id, defaulting to saml', () => {
    expect(makeProvider().provider.id).toBe('saml')
    expect(makeProvider({ providerId: 'okta' }).provider.id).toBe('okta')
  })
})

describe('the profile the IdP asserts', () => {
  const withProfile = (profile: unknown) =>
    makeClient({ validatePostResponseAsync: vi.fn(async () => ({ loggedOut: false, profile: profile as never })) })

  it('refuses a blank or oversize nameID', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    for (const nameID of ['', 'x'.repeat(513)]) {
      const { provider } = makeProvider({}, withProfile({ nameID }))
      await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
      })
    }
  })

  it('FINDING: a whitespace-only nameID passes the blank check', async () => {
    // The guard is a length test, so a space is a name. It reaches the just in
    // time provisioning hook as the identifier the account is keyed on, which is
    // the collapse the guard was written to prevent.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider({}, withProfile({ nameID: '   ' }))
    await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(signIns[0]?.profile.nameID).toBe('   ')
  })

  it('FINDING: the nameID format is never checked against the one the SP requires', async () => {
    // The default config asks for emailAddress and the metadata builder writes
    // that into the SP descriptor, but the response is accepted whatever format
    // it carries. A transient nameID changes on every login, so just in time
    // provisioning keyed on it creates a new account each time.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider(
      {},
      withProfile({ nameID: 'AAdzZWNyZXQ', nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' }),
    )
    await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(signIns[0]?.profile.nameIDFormat).toContain('transient')
  })

  it('FINDING: profileToIdentityProfile is offered on the options and never called', async () => {
    // The oauth providers read this hook and refuse the sign-in when it rejects
    // the profile. The SAML provider declares the identical option and hands the
    // raw profile straight to `onSignIn`, so a consumer who wrote a projection
    // to sanitise IdP attributes has written dead code.
    const adapter = new MemoryAdapter<MyProfile>()
    const project = vi.fn(() => ({}) as MyProfile)
    const { provider, signIns } = makeProvider({ profileToIdentityProfile: project })

    await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(project).not.toHaveBeenCalled()
    expect(signIns[0]?.profile).toMatchObject({ nameID: 'sso-user-1' })
  })

  it('FINDING: every attribute the IdP sends reaches the provisioning hook unfiltered', async () => {
    // Only `nameID` is validated. Whatever else the assertion carried, including
    // an attribute named like one of the app's own claims, is what `onSignIn`
    // receives, and the consumer is the first code to look at it.
    const adapter = new MemoryAdapter<MyProfile>()
    const attributes = {
      email: 'victim@corp.example',
      isAdmin: 'true',
      roles: ['owner', 'billing'],
    }
    const { provider, signIns } = makeProvider({}, withProfile({ attributes, nameID: 'sso-user-1' }))

    await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(signIns[0]?.profile.attributes).toEqual(attributes)
  })

  it('FINDING: an email asserted by the IdP is not checked against the nameID it arrived with', async () => {
    // Provisioning that looks the account up by `email`, which the hook's own
    // documentation suggests, keys on a field no guard covers. Two nameIDs
    // asserting the same address resolve to the same account.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider({}, withProfile({ email: 'ceo@corp.example', nameID: 'intern-42' }))
    await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(signIns[0]?.profile).toMatchObject({ email: 'ceo@corp.example', nameID: 'intern-42' })
  })

  it('refuses a logout response arriving on the sign-in path', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider(
      {},
      makeClient({ validatePostResponseAsync: vi.fn(async () => ({ loggedOut: true, profile: null })) }),
    )
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('refuses a null profile even when the client reports success', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider(
      {},
      makeClient({ validatePostResponseAsync: vi.fn(async () => ({ loggedOut: false, profile: null })) }),
    )
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })
})

describe('the cost of an attempt', () => {
  it('FINDING: complete never touches the limiter, so signature verification is unthrottled', async () => {
    // Password sign-in is rate limited. This path hands a megabyte of XML to a
    // signature verifier with no per-ip or per-identity budget, so an
    // unauthenticated client can spend the process's CPU at will.
    const adapter = new MemoryAdapter<MyProfile>()
    const ctx = ctxFor(adapter)
    const consume = vi.spyOn(ctx.limiter, 'consume')
    const { provider } = makeProvider()

    for (let i = 0; i < 10; i++) await provider.complete(ctx, { SAMLResponse: 'x' })
    expect(consume).not.toHaveBeenCalled()
  })

  it('FINDING: begin is unthrottled too, so the IdP redirect is a free amplifier', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const ctx = ctxFor(adapter)
    const consume = vi.spyOn(ctx.limiter, 'consume')
    const { provider } = makeProvider()

    for (let i = 0; i < 10; i++) await provider.begin(ctx, { host: 'app.test', relayState: 's' })
    expect(consume).not.toHaveBeenCalled()
  })

  it('FINDING: the size cap counts utf-16 code units, so the byte ceiling is twice what it says', async () => {
    // A body just under the one mebibyte cap can be two megabytes of UTF-8 on
    // the wire and in the parser.
    const adapter = new MemoryAdapter<MyProfile>()
    const { client, provider } = makeProvider()
    const body = '\u{1F424}'.repeat(500_000) // 1,000,000 code units, 2 MB of utf-8.

    await provider.complete(ctxFor(adapter), { SAMLResponse: body })
    const sent = (client.validatePostResponseAsync as ReturnType<typeof vi.fn>).mock.calls[0]?.[0].SAMLResponse
    expect(Buffer.byteLength(sent)).toBeGreaterThan(1_048_576)
  })

  it('refuses a body past the cap before the parser sees it', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { client, provider } = makeProvider()
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'a'.repeat(1_048_577) })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(client.validatePostResponseAsync).not.toHaveBeenCalled()
  })
})

describe('what a failed attempt tells the caller', () => {
  it('keeps the client’s error text off the wire and on the bus', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const events = new InMemoryEvents()
    const seen: Array<{ reason: string }> = []
    events.on('signin.failed', (p) => {
      seen.push(p as never)
    })
    const { provider } = makeProvider(
      {},
      makeClient({
        validatePostResponseAsync: vi.fn(async () => {
          throw new Error('<saml:Assertion ID="_abc">signature mismatch</saml:Assertion>')
        }),
      }),
    )

    const detail = await provider
      .complete(ctxFor(adapter, { events }), { SAMLResponse: 'x' })
      .then(() => undefined)
      .catch((e: { meta: { detail: string } }) => e.meta.detail)
    expect(detail).toBe('SAMLResponse validation failed')
    expect(seen[0]?.reason).toContain('signature mismatch')
  })

  it('FINDING: the detail string still distinguishes why an attempt failed', async () => {
    // Three failures produce three different strings: a malformed body, a
    // rejected signature, and an unusable profile. That is a usable oracle for
    // an attacker probing which part of a forged assertion the verifier
    // objected to, even though none of the strings carries the XML.
    const adapter = new MemoryAdapter<MyProfile>()
    const detailOf = async (provider: ReturnType<typeof makeProvider>['provider'], body: string) =>
      provider
        .complete(ctxFor(adapter), { SAMLResponse: body })
        .catch((e: { meta: { detail: string } }) => e.meta.detail)

    const tooBig = await detailOf(makeProvider().provider, '')
    const badSig = await detailOf(
      makeProvider(
        {},
        makeClient({
          validatePostResponseAsync: vi.fn(async () => {
            throw new Error('bad signature')
          }),
        }),
      ).provider,
      'x',
    )
    const badProfile = await detailOf(
      makeProvider(
        {},
        makeClient({ validatePostResponseAsync: vi.fn(async () => ({ loggedOut: false, profile: { nameID: '' } })) }),
      ).provider,
      'x',
    )

    expect(new Set([tooBig, badSig, badProfile]).size).toBe(3)
  })

  it('FINDING: a failure inside the provisioning hook escapes untyped', async () => {
    // `onSignIn` is consumer code called after every other guard has passed. It
    // is not wrapped, so a store outage surfaces as whatever the consumer threw
    // rather than as an AuthError an adapter knows how to render.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider({
      onSignIn: async () => {
        throw new Error('identity store unreachable')
      },
    })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toThrow(
      'identity store unreachable',
    )
  })

  it('FINDING: begin reports a caller mistake as a misconfiguration, not a bad request', async () => {
    // `relayState` and `host` come from the request, so a missing one is a four
    // hundred. AUTH_MISCONFIGURED is the code this library uses for boot-time
    // wiring errors, and it carries a five hundred status.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider()
    const err = await provider
      .begin(ctxFor(adapter), { host: 'app.test', relayState: '' })
      .then(() => undefined)
      .catch((e: { code: string; status: number }) => e)
    expect(err).toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    expect(err?.status).toBeGreaterThanOrEqual(500)
  })
})
