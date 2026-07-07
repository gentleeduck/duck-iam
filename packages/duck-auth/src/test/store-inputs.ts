/**
 * Total-input factory helpers for store-contract tests. Store contracts are
 * total (every nullable field explicit), so these fill the `null` defaults and
 * let a test pass only the fields it cares about — no casts, no `undefined`.
 */

import type { Credential, Identity } from '../core/types/identity'
import type { Session } from '../core/types/session'

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
