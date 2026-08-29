/**
 * Demo `AuthEngine` wired with every auth flow duck-auth ships:
 * passwords (Argon2id), magic-link (console), OAuth (Google/GitHub;
 * skipped when env keys missing), passkey (WebAuthn), TOTP/backup
 * codes. Storage: Postgres via the bundled Drizzle adapter.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { drizzlePgStorage } from '@gentleduck/auth/adapters/drizzle/pg'
import { AuthConsoleChannel } from '@gentleduck/auth/channels/console'
import { createAuth } from '@gentleduck/auth/core'
import { CookieTransport } from '@gentleduck/auth/core/transport'
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

export const storage = drizzlePgStorage<DemoProfile>(
  process.env.DATABASE_URL ?? 'postgres://duck:duck_dev_pw@localhost:5433/duck_auth_demo',
)

export const auth = createAuth<DemoProfile>({
  baseUrl: BASE_URL,
  channels: { email: new AuthConsoleChannel() },
  limiter: new MemoryLimiter({ max: 30, windowMs: 60_000 }),
  providers: [
    passwords({ hasher: new Argon2idHasher() }),
    () =>
      magicLink<DemoProfile>({
        autoCreateIdentity: true,
        autoCreateProfile: (email) => ({ username: email, email, emailVerified: false }),
        callbackPath: '/auth/magic-link/verify',
        channels: { email: new AuthConsoleChannel() },
        findIdentityByEmail: (e) => storage.identities.findByEmail(e),
      }),
    process.env.GOOGLE_CLIENT_ID &&
      google<DemoProfile>({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
        redirectUri: `${BASE_URL}/auth/providers/google/callback`,
        stateSigningSecret: STATE,
      }),
    process.env.GITHUB_CLIENT_ID &&
      github<DemoProfile>({
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '',
        redirectUri: `${BASE_URL}/auth/providers/github/callback`,
        stateSigningSecret: STATE,
      }),
    () =>
      passkey<DemoProfile>({
        expectedOrigins: BASE_URL,
        findIdentityByEmail: (e) => storage.identities.findByEmail(e),
        rpID: 'localhost',
        rpName: 'duck-auth-demo',
      }),
  ],
  stores: storage,
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})
