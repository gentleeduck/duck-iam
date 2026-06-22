/** Test helpers - `authCreateTest()` wires an in-memory AuthEngine for e2e-style tests. */

import { AuthMemoryAdapter } from '../adapters/memory'
import { AuthEngine } from '../core/auth'
import { AuthScryptHasher } from '../core/password/scrypt'
import { AuthBearerTransport } from '../core/transport/bearer'
import { AuthMemoryLimiter } from '../limiters/memory'

/** Build a fully-wired `AuthEngine` for tests; defaults to in-memory adapter + bearer transport + scrypt hasher. */
export function authCreateTest<Profile = unknown, Tenant = string, OrgMeta = unknown>(
  overrides: AuthTest.IOverrides<Profile, Tenant, OrgMeta> = {},
): AuthEngine<Profile, Tenant, OrgMeta> {
  const adapter = overrides.adapter ?? new AuthMemoryAdapter<Profile, OrgMeta>()
  const transport = overrides.transport ?? new AuthBearerTransport()
  const limiter = overrides.limiter ?? new AuthMemoryLimiter({ max: 1000, windowMs: 60_000 })
  const hasher = overrides.hasher ?? new AuthScryptHasher()

  const config: AuthEngine.IConfig<Profile, Tenant, OrgMeta> = {
    baseUrl: overrides.baseUrl ?? 'http://localhost:0',
    transport,
    stores: {
      identities: overrides.identities ?? adapter.identities,
      sessions: overrides.sessions ?? adapter.sessions,
      credentials: overrides.credentials ?? adapter.credentials,
      ...(overrides.orgs !== undefined && { orgs: overrides.orgs }),
    },
    limiter,
    passwords: { hasher, ...(overrides.passwords ?? {}) },
    ...(overrides.events !== undefined && { events: overrides.events }),
    ...(overrides.providers !== undefined && { providers: overrides.providers }),
  }

  return new AuthEngine<Profile, Tenant, OrgMeta>(config)
}

export namespace AuthTest {
  export interface IOverrides<Profile = unknown, _Tenant = string, OrgMeta = unknown> {
    /** Drop-in replacement for the bundled AuthMemoryAdapter. */
    adapter?: AuthMemoryAdapter<Profile, OrgMeta>
    /** Override the identities store individually (adapter still backs the rest). */
    identities?: AuthEngine.IConfig<Profile>['stores']['identities']
    sessions?: AuthEngine.IConfig<Profile>['stores']['sessions']
    credentials?: AuthEngine.IConfig<Profile>['stores']['credentials']
    orgs?: AuthEngine.IConfig<Profile, string, OrgMeta>['stores']['orgs']
    transport?: AuthEngine.IConfig<Profile>['transport']
    limiter?: AuthEngine.IConfig<Profile>['limiter']
    events?: AuthEngine.IConfig<Profile>['events']
    providers?: AuthEngine.IConfig<Profile>['providers']
    passwords?: Omit<NonNullable<AuthEngine.IConfig<Profile>['passwords']>, 'hasher'>
    hasher?: NonNullable<AuthEngine.IConfig<Profile>['passwords']>['hasher']
    baseUrl?: string
  }
}
