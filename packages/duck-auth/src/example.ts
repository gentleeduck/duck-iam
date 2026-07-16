/**
 * Worked example: wiring @gentleduck/auth with providers + idempotency.
 *
 * This file lives inside the package, so it imports through the `~/` source
 * alias. A real consumer uses the published entry points instead — the
 * equivalent public import is shown in a comment beside each one:
 *
 *   import { createAuth } from '@gentleduck/auth/core'
 *   import { AuthBearerTransport } from '@gentleduck/auth/core/transport'
 *   import { MemoryAdapter } from '@gentleduck/auth/adapters/memory'
 *   import { AuthMemoryLimiter } from '@gentleduck/auth/limiters/memory'
 *   import { passwords, ScryptHasher } from '@gentleduck/auth/providers/password'
 *   import { mfaProvider } from '@gentleduck/auth/providers/mfa'
 *   import { apiKeyProvider } from '@gentleduck/auth/providers/api-key'
 *   import { IdempotencyFacet, MemoryIdempotencyStore, type Idempotency }
 *     from '@gentleduck/auth/core'   // idempotency lives under core
 */

import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config'
import { type Idempotency, idempotency, memoryIdempotency } from '~/core/idempotency'
import type { TenantContext } from '~/core/tenant'
import { BearerTransport } from '~/core/transport/bearer.transport'
import { memoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

// --- 1. Storage + transport ------------------------------------------------
// MemoryAdapter is dev/test only (strict() rejects it in production). Swap in
// RedisSessionStore / a Drizzle adapter for real deployments.
const adapter = new MemoryAdapter()

// --- 2. The auth engine, with three providers wired in ---------------------
// Each provider is registered in `providers[]`. Password takes a config
// object; mfa + api-key are thunks that bind to the engine's stores/events.
export const auth = createAuth({
  baseUrl: 'http://localhost:3000',
  transport: new BearerTransport(),
  stores: {
    identities: adapter.identities,
    sessions: adapter.sessions,
    credentials: adapter.credentials,
  },
  limiter: memoryLimiter({ max: 5, windowMs: 60_000 }),
  providers: [
    // Email + password sign-in. Argon2idHasher is the production default;
    // ScryptHasher keeps this example dependency-free.
    passwords({ hasher: new ScryptHasher() }),
    // TOTP / backup-code MFA. Resolve later via `auth.mfa`.
    mfaProvider(),
    // Machine-to-machine API keys. Resolve later via `auth.apiKeys`.
    apiKeyProvider(),
  ],
  idempotency: idempotency(memoryIdempotency()),
})

// The registered providers surface as typed facets on the engine. These
// getters throw AUTH_PROVIDER_NOT_REGISTERED if the provider was omitted.
void auth.passwords // password verification / registration
void auth.mfa // enroll / verify second factors
void auth.apiKeys // mint / verify API keys

// Side-effect counter so the demo can prove the executor runs exactly once.
let chargesExecuted = 0

/**
 * Example: a "charge the customer once" handler. Framework adapters pull the
 * `Idempotency-Key` header (name available via `idempotency.headerName`) and
 * pass it here; the executor only ever runs once per key.
 */
export async function chargeOnce(idempotencyKey: string, tenant: TenantContext, identityId: string) {
  return auth.idempotency.handle(
    idempotencyKey,
    tenant,
    async (): Promise<Idempotency.CachedResponse> => {
      // ...the real mutation (create order, charge card, mint token)...
      chargesExecuted += 1
      return { status: 201, body: { charged: true, amount: 4200 }, createdAt: new Date() }
    },
    { identityId },
  )
}

// --- 4. Run the idempotency demo -------------------------------------------
async function main(): Promise<void> {
  const key = 'order-9f3a-2f77'
  const tenant: TenantContext = { tenantId: 'acme' }

  const first = await chargeOnce(key, tenant, 'user-1')
  const replay = await chargeOnce(key, tenant, 'user-1')

  // Same key -> identical replayed response; the executor ran exactly once.
  console.log('first :', first.status, JSON.stringify(first.body))
  console.log('replay:', replay.status, JSON.stringify(replay.body))
  console.log('executor runs:', chargesExecuted) // -> 1, despite two calls
  console.log('idempotency header:', auth.idempotency.headerName)
}

// Executed only when this file is run directly (`bun run src/example.ts`).
if (import.meta.main) {
  void main()
}
