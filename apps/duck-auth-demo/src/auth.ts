/**
 * Demo `AuthEngine` wired with every auth flow duck-auth ships:
 * passwords (Argon2id), magic-link (logged to the console), OAuth (Google/GitHub;
 * skipped when env keys missing), passkey (WebAuthn), TOTP/backup
 * codes. Storage: Postgres via the bundled Drizzle adapter.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { drizzlePgAdapter } from '@gentleduck/auth/adapters/drizzle/pg'
import type { Deliver } from '@gentleduck/auth/core'
import { createAuth } from '@gentleduck/auth/core'
import { CookieTransport, memoryDPoPNonceStore } from '@gentleduck/auth/core/transport'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { magicLink } from '@gentleduck/auth/providers/magic-link'
import { github } from '@gentleduck/auth/providers/oauth/github'
import { google } from '@gentleduck/auth/providers/oauth/google'
import { passkey } from '@gentleduck/auth/providers/passkey'
import { Argon2idHasher, passwords } from '@gentleduck/auth/providers/passwords'

export interface DemoProfile {
  username: string
  email: string
  emailVerified: boolean
  name?: string
  [key: string]: unknown
}

const BASE_URL = process.env.BASE_URL ?? 'http://localhost:8787'
const STATE = process.env.OAUTH_STATE_SECRET ?? 'demo-state-signing-secret-change-me-32-chars'

/** Both oauth providers burn each state at its callback, and name a state cookie an http host keeps. */
const OAUTH = {
  nonceStore: memoryDPoPNonceStore(),
  stateCookie: { name: 'duck-oauth', secure: false },
  stateSigningSecret: STATE,
}

export const adapter = drizzlePgAdapter<Record<string, unknown>, DemoProfile>(
  process.env.DATABASE_URL ?? 'postgres://duck:duck_dev_pw@localhost:5433/duck_auth_demo',
)

/** Stands in for the mailer a real deployment would reach for. Throwing here is how a failure is
 *  reported: the flow answers the caller the same either way and emits `signin.failed`. */
const deliver: Deliver = async ({ identity, kind, vars }) => {
  console.log(`[${kind}] -> ${identity.profile.email}`, vars.url)
}

export const auth = createAuth<DemoProfile>({
  baseUrl: BASE_URL,
  deliver,
  limiter: new MemoryLimiter({ max: 30, windowMs: 60_000 }),
  providers: [
    passwords({ hasher: new Argon2idHasher() }),
    // A thunk, so magic-link binds to the same `deliver` the engine carries rather than its own copy.
    (_engine, send) =>
      magicLink<DemoProfile>({
        autoCreateIdentity: true,
        autoCreateProfile: (email) => ({ username: email, email, emailVerified: false }),
        callbackPath: '/auth/magic-link/verify',
        deliver: send,
        findIdentityByEmail: (e) => adapter.identities.find({ email: e }),
      }),
    process.env.GOOGLE_CLIENT_ID &&
      google<DemoProfile>({
        ...OAUTH,
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
        redirectUri: `${BASE_URL}/auth/providers/oauth:google/callback`,
      }),
    process.env.GITHUB_CLIENT_ID &&
      github<DemoProfile>({
        ...OAUTH,
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '',
        redirectUri: `${BASE_URL}/auth/providers/oauth:github/callback`,
      }),
    () =>
      passkey<DemoProfile>({
        expectedOrigins: BASE_URL,
        findIdentityByEmail: (e) => adapter.identities.find({ email: e }),
        rpID: 'localhost',
        rpName: 'duck-auth-demo',
      }),
  ],
  stores: adapter,
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})
