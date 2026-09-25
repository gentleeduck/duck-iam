import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { createAuth } from '~/core/config'
import type { Deliver } from '~/core/flows'
import { type Idempotency, memoryIdempotency } from '~/core/idempotency'
import type { TenantContext } from '~/core/tenant'
import { bearerTransport } from '~/core/transport'
import { memoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { magicLink } from '~/providers/magic-link'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

const adapter = new MemoryAdapter()

/**
 * Every outbound token the library mints arrives here: magic links, email verification, password resets,
 * account deletion and its undo link. The URL in `vars` is already signed; the host picks the transport
 * and writes the template. Throwing is how a failure is reported — the flow answers its caller the same
 * either way, so a refusal cannot be used to ask whether an address exists, and reaches the operator as a
 * `signin.failed` event instead. What you throw is never read into that event: it carries the recipient
 * and the rendered body, token URL and all.
 */
const deliver: Deliver = async ({ identity, kind, vars }) => {
  const to = identity.profile.email
  switch (kind) {
    case 'magic-link':
      return mail(to, 'Your sign-in link', `Tap to sign in: ${vars.url}`)
    case 'password-reset':
      return mail(to, 'Reset your password', `This link expires in ${vars.ttlMin} minutes: ${vars.url}`)
    case 'email-verification':
      return mail(to, 'Confirm your address', `Confirm it here: ${vars.url}`)
    case 'account-deletion':
      return mail(to, 'Confirm account deletion', `Confirm here: ${vars.url}`)
    case 'account-deletion-cancel':
      return mail(to, 'Undo account deletion', `Changed your mind? ${vars.url}`)
  }
}

/** Stands in for the mailer a deployment would reach for; a real one would throw on a refusal. */
async function mail(to: unknown, subject: string, body: string): Promise<void> {
  console.log(`-> ${String(to)} | ${subject}\n   ${body}`)
}

export const auth = createAuth({
  baseUrl: 'http://localhost:3000',
  deliver,
  transport: bearerTransport(),
  stores: adapter,
  limiter: memoryLimiter({ max: 5, windowMs: 60_000 }),
  providers: [
    passwords({ hasher: new ScryptHasher() }),
    mfaProvider(),
    apiKeyProvider(),
    // A thunk, so the provider binds to the engine's own `deliver` rather than being handed a second one.
    (_engine, send) =>
      magicLink({
        autoCreateIdentity: true,
        autoCreateProfile: (email) => ({ email, username: email }),
        deliver: send,
        findIdentityByEmail: (email) => orNull(adapter.identities.find({ email })),
      }),
  ],
  idempotency: memoryIdempotency(),
})

void auth.passwords
void auth.mfa
void auth.apiKeys
void auth.events.emit

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

  // Both answer `{ ok: true }` and both get a link: `autoCreateIdentity` makes this one flow for
  // signing in and signing up. Drop it and the unknown address still answers `{ ok: true }` - the
  // response is not a way to ask whether an account exists - but no link goes out for it.
  await auth.identities.create({ profile: { email: 'ada@example.com', username: 'ada' } })
  await auth.flows.beginProvider('magic-link', { email: 'ada@example.com' })
  await auth.flows.beginProvider('magic-link', { email: 'new-signup@example.com' })
}

// Executed only when this file is run directly (`bun run src/example.ts`).
if (import.meta.main) {
  void main()
}
