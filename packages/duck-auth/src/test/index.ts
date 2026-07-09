/** Test helpers - `authCreateTest()` wires an in-memory AuthEngine for e2e-style tests. */

import { MemoryAdapter } from '../adapters/memory'
import type { AuthEngineTypes } from '../core/engine'
import { AuthEngine } from '../core/engine'
import type { Identity } from '../core/identities/identities.types'
import { BearerTransport } from '../core/transport/bearer.transport'
import { AuthMemoryLimiter } from '../limiters/memory'
import { type ApiKeys, apiKeyProvider } from '../providers/api-key'
import { type Mfa, mfaProvider } from '../providers/mfa'
import { type Passwords, passwords, ScryptHasher } from '../providers/passwords'

export namespace Test {
  export interface Overrides<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase, Tenant = string, OrgMeta = unknown> {
    /** Drop-in replacement for the bundled AuthMemoryAdapter. */
    adapter?: MemoryAdapter<Profile, OrgMeta>
    /** Override the identities store individually (adapter still backs the rest). */
    identities?: AuthEngineTypes.Config<Profile>['stores']['identities']
    sessions?: AuthEngineTypes.Config<Profile>['stores']['sessions']
    credentials?: AuthEngineTypes.Config<Profile>['stores']['credentials']
    orgs?: AuthEngineTypes.Config<Profile, string, OrgMeta>['stores']['orgs']
    transport?: AuthEngineTypes.Config<Profile>['transport']
    limiter?: AuthEngineTypes.Config<Profile>['limiter']
    events?: AuthEngineTypes.Config<Profile>['events']
    providers?: AuthEngineTypes.Config<Profile, Tenant, OrgMeta>['providers']
    /** Password provider tuning (minLength/maxLength/rejectCommon/compliance). */
    passwords?: Partial<Passwords.Config>
    /** MFA provider tuning (issuer/backupCodeCount/backupCodeLen/compliance). */
    mfa?: Mfa.ConfigInput
    /** API-key provider tuning (prefix/randomBytes/compliance). */
    apiKeys?: ApiKeys.ConfigInput
    baseUrl?: string
  }
}

/** Build a fully-wired `AuthEngine` for tests; defaults to in-memory adapter + bearer transport + scrypt hasher. */
export function createTest<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase, Tenant = string, OrgMeta = unknown>(
  overrides: Test.Overrides<Profile, Tenant, OrgMeta> = {},
): AuthEngine<Profile, Tenant, OrgMeta> {
  const adapter = overrides.adapter ?? new MemoryAdapter<Profile, OrgMeta>()
  const transport = overrides.transport ?? new BearerTransport()
  const limiter = overrides.limiter ?? new AuthMemoryLimiter({ max: 1000, windowMs: 60_000 })
  const hasher = overrides.passwords?.hasher ?? new ScryptHasher()

  const config: AuthEngineTypes.Config<Profile, Tenant, OrgMeta> = {
    baseUrl: overrides.baseUrl ?? 'http://localhost:0',
    transport,
    stores: {
      identities: overrides.identities ?? adapter.identities,
      sessions: overrides.sessions ?? adapter.sessions,
      credentials: overrides.credentials ?? adapter.credentials,
      ...(overrides.orgs !== undefined && { orgs: overrides.orgs }),
    },
    limiter,
    providers: [
      passwords(overrides?.passwords?? {
        hasher: hasher
      }),
      mfaProvider(overrides.mfa),
      apiKeyProvider(overrides.apiKeys),
      ...(overrides.providers ?? []),
    ],
    ...(overrides.events !== undefined && { events: overrides.events }),
  }

  return new AuthEngine<Profile, Tenant, OrgMeta>(config)
}

