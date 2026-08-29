/**
 * `createAuth` is the documented entry point, so anything its config type
 * accepts and its body does not forward is a setting an operator believes they
 * turned on. That failure is silent by construction: the key type-checks, the
 * engine builds, and nothing reports the drop. One instance of it has already
 * been fixed here (idempotency, which fell back to the memory store and made
 * strict refuse to boot). These cases enumerate the surface and check the rest.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { idempotency } from '~/core/idempotency'
import { MemoryIdempotency } from '~/core/idempotency/idempotency.memory'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { createAuth } from '../config'
import type { AuthDefine } from '../config.types'

const stores = () => {
  const adapter = new MemoryAdapter()
  return { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions }
}

const base = (): AuthDefine.Cfg => ({ baseUrl: 'https://app.test', stores: stores() })

describe('every knob the config type accepts reaches the engine', () => {
  it('forwards the stores, the transport, the limiter and the bus', () => {
    const transport = new JwtTransport({
      issuer: 'https://app.test',
      signKey: { key: 'secret-32-bytes-of-test-material', kid: 'k1' },
      ttlMs: 60_000,
      verifyKeys: [{ key: 'secret-32-bytes-of-test-material', kid: 'k1' }],
    })
    const events = new InMemoryEvents()
    const limiter = new MemoryLimiter()
    const auth = createAuth({ ...base(), events, limiter, transport })

    expect(auth.transport).toBe(transport)
    expect(auth.cfg.limiter).toBe(limiter)
  })

  it('wraps the supplied bus in the audit stamper rather than holding it directly', async () => {
    // Worth pinning: `auth.events` is not the object that was passed in, so a
    // caller comparing identities sees a different bus. Emissions still reach the
    // listeners registered on the original.
    const events = new InMemoryEvents()
    const seen: unknown[] = []
    events.on('maintenance.off', (p) => {
      seen.push(p)
    })
    const auth = createAuth({ ...base(), events })

    expect(auth.events).not.toBe(events)
    await auth.events.emit('maintenance.off', {})
    expect(seen).toHaveLength(1)
  })

  it('forwards the idempotency store rather than falling back to the memory one', () => {
    // The regression this pins: dropping the key here made strict() refuse to
    // boot production, because the engine had quietly substituted the in-memory
    // implementation that cannot dedupe across instances.
    const store = idempotency(new MemoryIdempotency({ development: true }))
    const auth = createAuth({ ...base(), idempotency: store })
    expect(auth.idempotency).toBe(store)
  })

  it('forwards the session windows and the identity limits', () => {
    const auth = createAuth({
      ...base(),
      identities: { profileMaxBytes: 512 },
      session: { absoluteTtlMs: 120_000, freshnessMs: 1_000, ttlMs: 60_000 },
    })
    expect(auth.cfg.session).toMatchObject({ ttlMs: 60_000 })
    expect(auth.cfg.identities).toMatchObject({ profileMaxBytes: 512 })
  })

  it('forwards the hijack policy', () => {
    const auth = createAuth({ ...base(), hijack: { onIpChange: 'revoke' } })
    expect(auth.cfg.hijack).toMatchObject({ onIpChange: 'revoke' })
  })

  it('registers providers, and skips the falsy entries', () => {
    const auth = createAuth({
      ...base(),
      providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }), false, null, undefined, ''],
    })
    expect(auth.providers.has('password')).toBe(true)
    expect(auth.providers.list()).toHaveLength(1)
  })

  it('resolves a provider thunk against the constructed engine and the channels bundle', () => {
    const seen: Array<{ channels: unknown; sameEngine: boolean }> = []
    const channels = { email: { id: 'email', send: async () => undefined } as never }
    const auth = createAuth({
      ...base(),
      channels,
      providers: [
        (engine, chans) => {
          seen.push({ channels: chans, sameEngine: engine instanceof Object })
          return passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) })
        },
      ],
    })
    expect(auth.providers.has('password')).toBe(true)
    expect(seen[0]?.channels).toBe(channels)
  })

  it('refuses a plugins array rather than accepting one it cannot install', () => {
    // Installation is async and this factory is not, so the key used to be
    // accepted and dropped: an engine with an empty registry and no error.
    // It now names the call that does work.
    let installed = false
    expect(() =>
      createAuth({
        ...base(),
        plugins: [
          {
            id: 'my-plugin',
            install: async () => {
              installed = true
            },
          } as never,
        ],
      }),
    ).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    expect(installed).toBe(false)
  })

  it('an empty or absent plugins array is not an error', () => {
    expect(() => createAuth({ ...base(), plugins: [] })).not.toThrow()
    expect(() => createAuth(base())).not.toThrow()
  })

  it('a plugin installed through the engine does reach the registry', async () => {
    const auth = createAuth(base())
    await auth.use({ id: 'my-plugin', install: async () => undefined } as never)
    expect(auth.plugins.installed.has('my-plugin')).toBe(true)
  })

  it('refuses an oauth-wide state signing secret it has no way to apply', () => {
    // Each oauth provider takes its own `stateSigningSecret` at construction, so
    // a value set once at the top could never be applied. It used to be accepted
    // and ignored, which left the operator believing state was signed.
    expect(() => createAuth({ ...base(), oauth: { stateSigningSecret: 'top-level-secret' } })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('an oauth block without the secret is not an error', () => {
    expect(() => createAuth({ ...base(), oauth: {} })).not.toThrow()
  })

  it('FINDING: no key outside the two the engine knows is reported as unrecognised', () => {
    // There is no strict-key check anywhere in the path, so a typo in a config
    // key is accepted in silence. `sessions` instead of `session` is the one a
    // caller is most likely to write, and it disables the window they meant to
    // shorten.
    const auth = createAuth({ ...base(), sessions: { ttlMs: 1_000 } } as never)
    expect(auth.cfg.session).toBeUndefined()
  })
})

describe('the defaults it picks when a knob is omitted', () => {
  it('defaults to a secure cookie transport', () => {
    const auth = createAuth(base())
    expect(auth.transport).toBeInstanceOf(CookieTransport)
    expect((auth.transport as CookieTransport).secure).toBe(true)
  })

  it('builds without a limiter, an events bus or any provider', () => {
    const auth = createAuth(base())
    expect(auth.providers.list()).toEqual([])
    expect(auth.events).toBeDefined()
  })

  it('FINDING: with no limiter configured the engine builds and only strict complains', () => {
    // Rate limiting is optional at construction, so the ordinary path, build an
    // engine and mount it, has no throttle in front of sign-in unless the
    // operator remembers `strict`.
    const auth = createAuth(base())
    expect(auth.cfg.limiter).toBeUndefined()
    expect(() => auth.strict({ env: 'production' })).toThrow()
  })
})

describe('the strict flag', () => {
  it('runs at construction and refuses a production config that is not production ready', () => {
    expect(() => createAuth({ ...base(), strict: 'production' })).toThrow()
  })

  it('a development or test env is permissive', () => {
    expect(() => createAuth({ ...base(), strict: 'development' })).not.toThrow()
    expect(() => createAuth({ ...base(), strict: 'test' })).not.toThrow()
  })

  it('FINDING: omitting strict is the default, so nothing is checked unless asked', () => {
    // The same config that throws with `strict: 'production'` builds silently
    // without it, and the flag has to be remembered rather than opted out of.
    expect(() => createAuth(base())).not.toThrow()
  })

  it('FINDING: an unknown env string is accepted and read as truthy', () => {
    // `if (config.strict)` is a truthiness test and the value is handed straight
    // to `strict({ env })`. A misspelled environment does not fall back to the
    // strictest reading.
    expect(() => createAuth({ ...base(), strict: 'prod' as never })).not.toThrow()
  })

  it('FINDING: the string "false" enables strict, because only falsiness is checked', () => {
    // A flag threaded from an environment variable arrives as a string. `'false'`
    // is truthy, so an operator turning strict off turns it on.
    expect(() => createAuth({ ...base(), strict: 'false' as never })).not.toThrow()
    expect(() => createAuth({ ...base(), strict: '' as never })).not.toThrow()
  })
})

describe('the store triple', () => {
  it('forwards an org store when one is supplied and tolerates its absence', () => {
    const adapter = new MemoryAdapter()
    const withOrgs = createAuth({ ...base(), stores: { ...stores(), orgs: adapter.orgs } })
    expect(withOrgs.cfg.stores.orgs).toBe(adapter.orgs)
    expect(createAuth(base()).cfg.stores.orgs).toBeUndefined()
  })

  it('FINDING: a missing store surfaces as a TypeError at construction, not a misconfiguration', () => {
    // The three stores are required by the type only. A config assembled at
    // runtime that is missing one dereferences undefined rather than reporting
    // which store was absent.
    expect(() => createAuth({ baseUrl: 'https://app.test' } as never)).toThrow(TypeError)
  })

  it('FINDING: the base url is taken verbatim, with no scheme or shape check', () => {
    // It is the origin every redirect and cookie decision is measured against.
    // Nothing here parses it, so a trailing slash, a bare host or an empty string
    // all reach the facets that compare against it.
    for (const baseUrl of ['', 'app.test', 'https://app.test/', 'javascript:alert(1)']) {
      expect(() => createAuth({ ...base(), baseUrl })).not.toThrow()
    }
  })
})
