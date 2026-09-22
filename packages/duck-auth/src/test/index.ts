/** `authCreateTest()` wires an in-memory AuthEngine for e2e-style tests. */

/** The in-process redis double. It lives here rather than on `adapters/redis`, which is a production
 *  entry: an app reaching for it is writing a test, and the contract type it implements stays there. */
export { FakeRedis, fakeRedis } from '../core/drivers/redis-like'

import { MemoryAdapter } from '../adapters/memory'
import { AuthEngine, type Engine } from '../core/engine'
import type { Identities } from '../core/identities/identities.types'
import { BearerTransport } from '../core/transport/bearer.transport'
import { MemoryLimiter } from '../limiters/memory'
import { type ApiKeys, apiKeyProvider } from '../providers/api-key'
import { type Mfa, mfaProvider } from '../providers/mfa'
import { type Passwords, passwords, ScryptHasher } from '../providers/passwords'

/** Overrides a test harness may supply when building an engine. */
export namespace Test {
  export interface Overrides<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase, Tenant = string, OrgMeta = unknown> {
        /** Drop-in replacement for the bundled {@link MemoryAdapter}. */
    adapter?: MemoryAdapter<Profile, OrgMeta>
    /** Replace the whole store bag, the way a real deployment hands the engine an adapter. */
    stores?: Engine.Cfg<Profile, Tenant, OrgMeta>['stores']
    transport?: Engine.Cfg<Profile>['transport']
    limiter?: Engine.Cfg<Profile>['limiter']
    events?: Engine.Cfg<Profile>['events']
    providers?: Engine.Cfg<Profile, Tenant, OrgMeta>['providers']
    /** Password provider tuning (minLength/maxLength/rejectCommon/compliance). */
    passwords?: Partial<Passwords.Cfg>
    /** MFA provider tuning (issuer/backupCodeCount/backupCodeLen/compliance). */
    mfa?: Mfa.CfgInput
    /** API-key provider tuning (prefix/randomBytes/compliance). */
    apiKeys?: ApiKeys.CfgInput
    baseUrl?: string
  }
}

/** Build a fully-wired `AuthEngine` for tests; defaults to in-memory adapter + bearer transport + scrypt hasher. */
export function createTest<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase, Tenant = string, OrgMeta = unknown>(
  overrides: Test.Overrides<Profile, Tenant, OrgMeta> = {},
): AuthEngine<Profile, Tenant, OrgMeta> {
  const adapter = overrides.adapter ?? new MemoryAdapter<Profile, OrgMeta>()
  const transport = overrides.transport ?? new BearerTransport()
  const limiter = overrides.limiter ?? new MemoryLimiter({ max: 1000, windowMs: 60_000 })
  const hasher = overrides.passwords?.hasher ?? new ScryptHasher()

  const cfg: Engine.Cfg<Profile, Tenant, OrgMeta> = {
    baseUrl: overrides.baseUrl ?? 'http://localhost:0',
    transport,
    stores: overrides.stores ?? adapter,
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

  return new AuthEngine<Profile, Tenant, OrgMeta>(cfg)
}

