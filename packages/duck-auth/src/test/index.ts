/**
 * Test helpers.
 *
 * `createTestAuth()` wires up a fully-functional AuthRoot backed by
 * in-memory stores so consumers can write end-to-end-style tests without
 * orchestrating Redis / SQL / channels. Every store can be overridden
 * via the optional `overrides` arg so tests can substitute a real
 * adapter under test alongside the rest of the in-memory plumbing.
 */

import { MemoryAuthAdapter } from '../adapters/memory'
import { AuthRoot } from '../core/auth'
import { ScryptHasher } from '../core/password/scrypt'
import { BearerTransport } from '../core/transport/bearer'
import { MemoryLimiter } from '../limiters/memory'

/**
 * Build a fully-wired `AuthRoot` for use in tests. Defaults:
 *
 *   - `MemoryAuthAdapter` for identities / sessions / credentials / orgs
 *   - `BearerTransport` so tests can drive flows with synthetic
 *     `Authorization: Bearer ...` headers
 *   - `ScryptHasher` (Node built-in; no peerDep)
 *   - `MemoryLimiter` (token-bucket; 1000/min so tests are not gated)
 *   - `baseUrl = 'http://localhost:0'` (port 0 = unbound; tests should
 *     not rely on the URL being routable)
 *
 * Pass `overrides` to swap any stick in the bundle: the override
 * replaces the in-memory default for that key only; everything else
 * stays wired.
 *
 * @example
 * ```ts
 * import { createTestAuth } from '@gentleduck/auth/test'
 *
 * const auth = createTestAuth()
 * const { identity } = await auth.identities.create({ profile: { email: 'a@b.test' } })
 * ```
 */
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

/**
 * Namespace merge for `createTestAuth`. Holds the override shape so
 * consumers can `TestAuth.IOverrides` it without hunting through the
 * `AuthRoot.IConfig` tree.
 */
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
