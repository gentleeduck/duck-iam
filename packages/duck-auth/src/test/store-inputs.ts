/**
 * Total-input factory helpers for store-contract tests. Store contracts are
 * total (every nullable field explicit), so these fill the `null` defaults and
 * let a test pass only the fields it cares about — no casts, no `undefined`.
 */

import type { Session } from '../core/sessions/sessions.types'
import type { Credential, Identity } from '../core/types/identity'

/** Build a full {@link Identity.Me} fixture; every field present, nullables default to `null`. */
export function makeIdentity(over: Partial<Identity.Me> = {}): Identity.Me {
  return {
    id: 'id-1',
    tenantId: null,
    profile: { username: 'u', email: 'u@x.com' },
    providers: [],
    version: 1,
    emailVerified: false,
    createdAt: new Date(0),
    updatedAt: new Date(0),
    deletedAt: null,
    ...over,
  }
}

/** Build a full {@link Session.Me} fixture; every field present, nullables default to `null`. */
export function makeSession(over: Partial<Session.Me> = {}): Session.Me {
  const now = new Date()
  return {
    id: 'sid-1',
    identityId: 'id-1',
    tenantId: null,
    kind: 'user',
    aal: 1,
    factors: [],
    csrfHash: null,
    ip: null,
    userAgent: null,
    fingerprint: null,
    createdAt: now,
    rotatedAt: now,
    expiresAt: new Date(now.getTime() + 60_000),
    absoluteExpiresAt: new Date(now.getTime() + 60_000),
    fresh: true,
    actingAs: null,
    ...over,
  }
}

/** Build a total {@link Identity.CreateInput}; nullable fields default to `null`. */
export function identityInput<P>(over: Partial<Identity.CreateInput<P>> & { profile: P }): Identity.CreateInput<P> {
  return { providers: [], tenantId: null, emailVerified: false, ...over }
}

/** Build a total {@link Session.CreateInput}; nullable fields default to `null`. */
export function sessionInput(
  over: Partial<Session.CreateInput> &
    Pick<
      Session.CreateInput,
      | 'id'
      | 'identityId'
      | 'kind'
      | 'aal'
      | 'factors'
      | 'createdAt'
      | 'rotatedAt'
      | 'expiresAt'
      | 'absoluteExpiresAt'
      | 'fresh'
    >,
): Session.CreateInput {
  return { tenantId: null, csrfHash: null, ip: null, userAgent: null, fingerprint: null, actingAs: null, ...over }
}

/** Build a total {@link Credential.UpsertInput}; nullable fields default to `null`. */
export function credentialInput(
  over: Partial<Credential.UpsertInput> & Pick<Credential.UpsertInput, 'identityId' | 'kind' | 'secret'>,
): Credential.UpsertInput {
  return { tenantId: null, metadata: null, lastUsedAt: null, expiresAt: null, revokedAt: null, ...over }
}
