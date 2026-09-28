import { drizzlePgAdapter } from '@gentleduck/auth/adapters/drizzle/pg'
import { createAuth } from '@gentleduck/auth/core'
import { cookieTransport } from '@gentleduck/auth/core/transport'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { passwords } from '@gentleduck/auth/providers/passwords'
import type { AppDb } from './iam'

/** Required by `createAuth` even though nothing here builds an absolute URL from it (no
 *  email-verification/password-reset/account-deletion flow is wired into these examples, and
 *  those are the only callers that read it). Derived from `PORT` rather than hardcoded so it
 *  actually matches whichever framework is running: Express/Hono/Nest set `PORT` in their own
 *  `.env`, and Next's port is hardcoded to 3400 in its own `dev`/`start` scripts (never through
 *  `PORT`), which is exactly this fallback's default. */
const APP_URL = process.env.APP_URL ?? `http://localhost:${process.env.PORT ?? 3400}`

/** http, so neither cookie can carry `Secure`. */
const cookies = cookieTransport({ name: 'duckiam-sid', secure: false })

/** Password + cookie sessions only — duck-iam's examples demonstrate the authorization engine,
 *  not duck-auth's fuller feature set (no MFA, magic-link, OAuth, email verification here). */
export function buildAuth(db: AppDb) {
  return createAuth({
    baseUrl: APP_URL,
    limiter: new MemoryLimiter({ max: 30, windowMs: 60_000 }),
    stores: drizzlePgAdapter(db),
    transport: cookies,
    providers: [passwords()],
  })
}

export type AppAuth = ReturnType<typeof buildAuth>

/** The signed-in caller's identity id, or `null` for a guest — every framework's session
 *  middleware resolves this once per request from the duck-auth cookie. */
export async function resolveIdentityId(auth: AppAuth, headers: Headers): Promise<string | null> {
  const resolved = await auth.resolveSession({ headers }).orNull()
  return resolved?.identity?.id ?? null
}
