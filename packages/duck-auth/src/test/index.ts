/** Test helpers - `createTestAuth()` wires an in-memory AuthRoot for e2e-style tests. */

import { MemoryAuthAdapter } from '../adapters/memory'
import { AuthRoot } from '../core/auth'
import { ScryptHasher } from '../core/password/scrypt'
import { BearerTransport } from '../core/transport/bearer'
import { MemoryLimiter } from '../limiters/memory'

/** Build a fully-wired `AuthRoot` for tests; defaults to in-memory adapter + bearer transport + scrypt hasher. */
export function createTestAuth<Profile = unknown, Tenant = string, OrgMeta = unknown>(
  overrides: TestAuth.IOverrides<Profile, Tenant, OrgMeta> = {},
): AuthRoot<Profile, Tenant, OrgMeta> {
  const adapter = overrides.adapter ?? new MemoryAuthAdapter<Profile, OrgMeta>()
  const transport = overrides.transport ?? new BearerTransport()
  const limiter = overrides.limiter ?? new MemoryLimiter({ max: 1000, windowMs: 60_000 })
  const hasher = overrides.hasher ?? new ScryptHasher()

  const config: AuthRoot.IConfig<Profile, Tenant, OrgMeta> = {
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

  return new AuthRoot<Profile, Tenant, OrgMeta>(config)
}

export namespace TestAuth {
  export interface IOverrides<Profile = unknown, _Tenant = string, OrgMeta = unknown> {
    /** Drop-in replacement for the bundled MemoryAuthAdapter. */
    adapter?: MemoryAuthAdapter<Profile, OrgMeta>
    /** Override the identities store individually (adapter still backs the rest). */
    identities?: AuthRoot.IConfig<Profile>['stores']['identities']
    sessions?: AuthRoot.IConfig<Profile>['stores']['sessions']
    credentials?: AuthRoot.IConfig<Profile>['stores']['credentials']
    orgs?: AuthRoot.IConfig<Profile, string, OrgMeta>['stores']['orgs']
    transport?: AuthRoot.IConfig<Profile>['transport']
    limiter?: AuthRoot.IConfig<Profile>['limiter']
    events?: AuthRoot.IConfig<Profile>['events']
    providers?: AuthRoot.IConfig<Profile>['providers']
    passwords?: Omit<NonNullable<AuthRoot.IConfig<Profile>['passwords']>, 'hasher'>
    hasher?: NonNullable<AuthRoot.IConfig<Profile>['passwords']>['hasher']
    baseUrl?: string
  }
}
