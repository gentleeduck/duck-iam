/**
 * A SAML sign-in is a browser POSTing an assertion the relying party did not
 * ask for over a channel the relying party does not control, so the provider's
 * job is deciding which assertions belong to which request. The existing suites
 * cover the input caps, the nameID guard, and the error redaction.
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
      profile: { nameID: 'sso-user-1' } as Saml.Profile,
    })),
    ...over,
  }
}

/** A provider plus the calls its onSignIn hook received. */
function makeProvider(over: Partial<Saml.Options<MyProfile>> = {}, client = makeClient()) {
  const signIns: Array<{ profile: Saml.Profile; tenantId?: string }> = []
  const provider = saml<MyProfile>({
    // The suite's default is the unsolicited flow, so every test that is not about the binding can
    // keep calling `complete` with a bare response.
    allowUnsolicited: true,
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

  it('checks the relay state the IdP echoed back against the one begin issued', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const issued = new Set<string>()
    const { provider, signIns } = makeProvider({
      allowUnsolicited: false,
      verifyRelayState: async ({ relayState }) => issued.delete(relayState),
    })

    issued.add('state-abc')
    await provider.begin(ctxFor(adapter), { host: 'app.test', relayState: 'state-abc' })

    const intents = await provider.complete(ctxFor(adapter), { SAMLResponse: 'base64-xml', relayState: 'state-abc' })
    expect(intents[0]).toMatchObject({ type: 'startSession' })
    expect(signIns).toHaveLength(1)

    // Replaying the same relay state is no longer a request this app issued.
    await expect(
      provider.complete(ctxFor(adapter), { SAMLResponse: 'base64-xml', relayState: 'state-abc' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('refuses a response with no relay state unless unsolicited responses are opted into', async () => {
    // An assertion an attacker obtained for their own account, POSTed into a victim's browser, is
    // otherwise indistinguishable from one the victim asked for. That is SAML login CSRF.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider({ allowUnsolicited: false, verifyRelayState: async () => true })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'unsolicited' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })

    const unsolicited = makeProvider().provider
    expect((await unsolicited.complete(ctxFor(adapter), { SAMLResponse: 'unsolicited' }))[0]).toMatchObject({
      identityId: 'id-for-sso-user-1',
      type: 'startSession',
    })
  })

  it('refuses to be constructed with neither a relay-state check nor an explicit opt-in', () => {
    expect(() => makeProvider({ allowUnsolicited: false })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('consumes an assertion id once, so one captured body cannot be replayed', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const consumed = new Set<string>()
    const client = makeClient({
      validatePostResponseAsync: vi.fn(async () => ({
        loggedOut: false,
        profile: { ID: '_assertion-1', nameID: 'sso-user-1' } as Saml.Profile,
      })),
    })
    const { provider, signIns } = makeProvider(
      {
        replayStore: {
          consume: async (id) => {
            const fresh = !consumed.has(id)
            consumed.add(id)
            return fresh
          },
        },
      },
      client,
    )

    await provider.complete(ctxFor(adapter), { SAMLResponse: 'same-body' })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'same-body' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(signIns).toHaveLength(1)
  })

  it('refuses an assertion carrying no id rather than skipping the replay store wired for it', async () => {
    // The suite's default profile has no `ID`, which is also the shape an attacker controls. Skipping the
    // check for it means an operator who explicitly wired replay protection has none for exactly those
    // bodies, and nothing reports that the guard never ran. SAML 2.0 core requires `ID` on an assertion.
    const adapter = new MemoryAdapter<MyProfile>()
    const consumed: string[] = []
    const replayStore = {
      consume: async (id: string) => {
        consumed.push(id)
        return true
      },
    }

    const { provider, signIns } = makeProvider({ replayStore })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'no-id' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })

    // Blank is the same refusal: consumed as a key it would burn once and lock out every later one.
    const blank = makeProvider(
      { replayStore },
      makeClient({
        validatePostResponseAsync: vi.fn(async () => ({
          loggedOut: false,
          profile: { ID: '   ', nameID: 'sso-user-1' } as Saml.Profile,
        })),
      }),
    )
    await expect(blank.provider.complete(ctxFor(adapter), { SAMLResponse: 'blank-id' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })

    expect(signIns).toHaveLength(0)
    expect(blank.signIns).toHaveLength(0)
    expect(consumed).toHaveLength(0)
  })

  it('refuses a callbackUrl the client does not validate Destination against', () => {
    // Nothing here parses the response, so the client is what checks `Destination` and `Recipient`.
    // The two disagreeing meant this option was a presence test and nothing more.
    const client = Object.assign(makeClient(), { options: { callbackUrl: 'https://app.test/auth/saml/acs' } })
    expect(() => makeProvider({ callbackUrl: 'https://completely-different.example/acs' }, client)).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
    expect(() => makeProvider({ callbackUrl: 'https://app.test/auth/saml/acs' }, client)).not.toThrow()
  })

  it('hands the tenant to the relay-state check, so an assertion can be bound to one', async () => {
    // The tenant used to reach `onSignIn` as context rather than as a constraint, so one instance
    // serving several tenants accepted the same assertion under any of them.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider({
      allowUnsolicited: false,
      verifyRelayState: async ({ relayState, tenantId }) => relayState === `for-${tenantId}`,
    })

    await provider.complete(ctxFor(adapter, { tenantId: 'tenant-a' }), {
      SAMLResponse: 'x',
      relayState: 'for-tenant-a',
    })
    await expect(
      provider.complete(ctxFor(adapter, { tenantId: 'tenant-b' }), { SAMLResponse: 'x', relayState: 'for-tenant-a' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })

    expect(signIns.map((s) => s.tenantId)).toEqual(['tenant-a'])
  })
})

describe('the assurance level the session is given', () => {
  it('takes the assurance level from what the IdP says it did, not from a literal', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const withContext = (authnContext?: string) =>
      makeClient({
        validatePostResponseAsync: vi.fn(async () => ({
          loggedOut: false,
          profile: { ...(authnContext !== undefined && { authnContext }), nameID: 'sso-user-1' } as Saml.Profile,
        })),
      })

    // A password-only IdP used to mint a session satisfying every step-up requirement here.
    const password = makeProvider({}, withContext('urn:oasis:names:tc:SAML:2.0:ac:classes:Password')).provider
    expect((await password.complete(ctxFor(adapter), { SAMLResponse: 'x' }))[0]).toMatchObject({ aal: 1 })

    const silent = makeProvider({}, withContext()).provider
    expect((await silent.complete(ctxFor(adapter), { SAMLResponse: 'x' }))[0]).toMatchObject({ aal: 1 })

    const mfa = makeProvider({}, withContext('urn:oasis:names:tc:SAML:2.0:ac:classes:X509')).provider
    expect((await mfa.complete(ctxFor(adapter), { SAMLResponse: 'x' }))[0]).toMatchObject({ aal: 2 })
  })

  it('records the factor as saml, so audit can tell it from an oauth sign-in', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider()
    const [intent] = await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(intent).toMatchObject({ factors: [{ method: 'saml' }] })
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

  it('refuses a whitespace-only nameID, which a length test called a name', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider({}, withProfile({ nameID: '   ' }))
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(signIns).toHaveLength(0)
  })

  it('refuses a nameID format the SP did not ask for', async () => {
    // A transient nameID changes on every login, so provisioning keyed on it mints a new account
    // each time. The metadata builder writes emailAddress into the SP descriptor; this enforces it.
    const adapter = new MemoryAdapter<MyProfile>()
    const transient = withProfile({
      nameID: 'AAdzZWNyZXQ',
      nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    })
    await expect(
      makeProvider({}, transient).provider.complete(ctxFor(adapter), { SAMLResponse: 'x' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })

    // An SP that genuinely wants transient ids says so.
    const opted = makeProvider(
      { allowedNameIdFormats: ['urn:oasis:names:tc:SAML:2.0:nameid-format:transient'] },
      transient,
    ).provider
    await expect(opted.complete(ctxFor(adapter), { SAMLResponse: 'x' })).resolves.toBeDefined()
  })

  it('calls profileToIdentityProfile, and refuses the sign-in when it rejects the profile', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const project = vi.fn(() => ({}) as MyProfile)
    const { provider, signIns } = makeProvider({ profileToIdentityProfile: project })

    await provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(project).toHaveBeenCalledWith(expect.objectContaining({ nameID: 'sso-user-1' }))
    expect(signIns[0]?.profile).toMatchObject({ nameID: 'sso-user-1' })

    const refusing = makeProvider({
      profileToIdentityProfile: () => {
        throw new Error('attribute set is not one this app accepts')
      },
    }).provider
    await expect(refusing.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('passes only the attributes the SP declared, once it declares any', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const attributes = { email: 'victim@corp.example', isAdmin: 'true', roles: ['owner', 'billing'] }
    const client = withProfile({ attributes, nameID: 'sso-user-1' })

    // Absent a declaration, everything the assertion carried still reaches the hooks, which is what
    // `profileToIdentityProfile` is now called to sanitise.
    const open = makeProvider({}, client)
    await open.provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(open.signIns[0]?.profile.attributes).toEqual(attributes)

    const scoped = makeProvider({ allowedAttributes: ['roles'] }, client)
    await scoped.provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })
    expect(scoped.signIns[0]?.profile.attributes).toEqual({ roles: ['owner', 'billing'] })
  })

  it('refuses an asserted email that is not the nameID it arrived with', async () => {
    // Provisioning that looks the account up by `email`, which the hook's own documentation
    // suggests, keyed on a field no guard covered: two nameIDs asserting one address resolved to
    // one account. Only checked when the SP asks for an emailAddress nameID, which is the default.
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider, signIns } = makeProvider({}, withProfile({ email: 'ceo@corp.example', nameID: 'intern-42' }))
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'x' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(signIns).toHaveLength(0)

    const matching = makeProvider({}, withProfile({ email: 'ceo@corp.example', nameID: 'CEO@corp.example' })).provider
    await expect(matching.complete(ctxFor(adapter), { SAMLResponse: 'x' })).resolves.toBeDefined()
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
  it('spends limiter budget before handing anything to the signature verifier', async () => {
    // This path hands a megabyte of XML to a signature verifier, so an unauthenticated client could
    // spend the process's CPU at will. The bucket is per tenant by default; `limiterKey` narrows it.
    const adapter = new MemoryAdapter<MyProfile>()
    const ctx = ctxFor(adapter)
    const consume = vi.spyOn(ctx.limiter, 'consume')
    const { client, provider } = makeProvider()

    await provider.complete(ctx, { SAMLResponse: 'x' })
    expect(consume).toHaveBeenCalledTimes(1)

    // The memory limiter in this harness allows three.
    await provider.complete(ctx, { SAMLResponse: 'x' })
    await provider.complete(ctx, { SAMLResponse: 'x' })
    await expect(provider.complete(ctx, { SAMLResponse: 'x' })).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(client.validatePostResponseAsync).toHaveBeenCalledTimes(3)
  })

  it('spends budget on begin too, so the IdP redirect is not a free amplifier', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const ctx = ctxFor(adapter)
    const consume = vi.spyOn(ctx.limiter, 'consume')
    const { provider } = makeProvider()

    for (let i = 0; i < 3; i++) await provider.begin(ctx, { host: 'app.test', relayState: 's' })
    expect(consume).toHaveBeenCalledTimes(3)
    await expect(provider.begin(ctx, { host: 'app.test', relayState: 's' })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('takes a caller-supplied limiter key, for an app that knows the client address', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const ctx = ctxFor(adapter)
    const consume = vi.spyOn(ctx.limiter, 'consume')
    const { provider } = makeProvider({ limiterKey: (_c, phase) => `by-ip:203.0.113.9:${phase}` })

    await provider.complete(ctx, { SAMLResponse: 'x' })
    expect(consume).toHaveBeenCalledWith('by-ip:203.0.113.9:complete')
  })

  it('measures the size cap in utf-8 bytes, which is what reaches the parser', async () => {
    // A body just under the cap in utf-16 code units was two megabytes on the wire.
    const adapter = new MemoryAdapter<MyProfile>()
    const { client, provider } = makeProvider()
    const body = '\u{1F424}'.repeat(500_000) // 1,000,000 code units, 2 MB of utf-8.

    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: body })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    expect(client.validatePostResponseAsync).not.toHaveBeenCalled()
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
    expect(detail).toBe('SAMLResponse rejected')
    expect(seen[0]?.reason).toContain('signature mismatch')
  })

  it('gives every refusal the same detail, so it is not an oracle', async () => {
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

    expect(new Set([tooBig, badSig, badProfile])).toEqual(new Set(['SAMLResponse rejected']))
  })

  it('wraps a failure inside the provisioning hook, and keeps its text on the bus', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const events = new InMemoryEvents()
    const seen: Array<{ reason: string }> = []
    events.on('signin.failed', (p) => {
      seen.push(p as never)
    })
    const { provider } = makeProvider({
      onSignIn: async () => {
        throw new Error('identity store unreachable')
      },
    })
    await expect(provider.complete(ctxFor(adapter, { events }), { SAMLResponse: 'x' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
      meta: { detail: 'SAMLResponse rejected' },
    })
    expect(seen[0]?.reason).toContain('identity store unreachable')
  })

  it('reports a missing relayState or host as a bad request, not as a misconfiguration', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const { provider } = makeProvider()
    for (const input of [
      { host: 'app.test', relayState: '' },
      { host: '', relayState: 's' },
    ]) {
      const err = await provider
        .begin(ctxFor(adapter), input)
        .then(() => undefined)
        .catch((e: { code: string; status: number }) => e)
      expect(err).toMatchObject({ code: 'AUTH_INVALID_PARAMETERS', status: 400 })
    }
  })
})
