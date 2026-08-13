import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config'
import { type Idempotency, idempotency, memoryIdempotency } from '~/core/idempotency'
import type { TenantContext } from '~/core/tenant'
import { bearerTransport } from '~/core/transport'
import { memoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

const adapter = new MemoryAdapter()

export const auth = createAuth({
  baseUrl: 'http://localhost:3000',
  transport: bearerTransport(),
  stores: adapter,
  limiter: memoryLimiter({ max: 5, windowMs: 60_000 }),
  providers: [
    passwords({ hasher: new ScryptHasher() }),
    mfaProvider(),
    apiKeyProvider(),
  ],
  idempotency: idempotency(memoryIdempotency()),
})

void auth.passwords
void auth.mfa
void auth.apiKeys

let chargesExecuted = 0

export async function chargeOnce(idempotencyKey: string, tenant: TenantContext, identityId: string) {
  return auth.idempotency.handle(
    idempotencyKey,
    tenant,
    async (): Promise<Idempotency.CachedResponse> => {
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
