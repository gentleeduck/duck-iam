/**
 * Demo `AuthRoot` wired with every auth flow duck-auth ships:
 * password (Argon2id), magic-link (console), OAuth (google/github;
 * skipped when env keys missing), passkey (WebAuthn), TOTP/backup
 * codes. Storage: Postgres via the bundled Drizzle adapter.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { drizzlePgStorage } from '@gentleduck/auth/adapters/drizzle/pg'
import { ConsoleChannel } from '@gentleduck/auth/channels/console'
import { Argon2idHasher, CookieTransport, defineAuth } from '@gentleduck/auth/core'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { magicLink } from '@gentleduck/auth/providers/magic-link'
import { github } from '@gentleduck/auth/providers/oauth/github'
import { google } from '@gentleduck/auth/providers/oauth/google'
import { passkey } from '@gentleduck/auth/providers/passkey'
import { password } from '@gentleduck/auth/providers/password'

export interface DemoProfile {
  email: string
  emailVerified: boolean
  name?: string
}

const BASE_URL = process.env.BASE_URL ?? 'http://localhost:8787'
const STATE = process.env.OAUTH_STATE_SECRET ?? 'demo-state-signing-secret-change-me-32-chars'

const storage = drizzlePgStorage<DemoProfile>(
  process.env.DATABASE_URL ?? 'postgres://duck:duck_dev_pw@localhost:5433/duck_auth_demo',
)

export const auth = defineAuth<DemoProfile>({
  baseUrl: BASE_URL,
  channels: { email: new ConsoleChannel() },
  hasher: new Argon2idHasher(),
  limiter: new MemoryLimiter({ max: 30, windowMs: 60_000 }),
  oauth: { stateSigningSecret: STATE },
  providers: [
    (a) =>
      password<DemoProfile>({
        findIdentityByEmail: (e) => storage.identities.findByEmail(e, {}),
        passwords: a.passwords,
      }),
    () =>
      magicLink<DemoProfile>({
        autoCreateIdentity: true,
        autoCreateProfile: (email) => ({ email, emailVerified: false }),
        callbackPath: '/auth/magic-link/verify',
        channels: { email: new ConsoleChannel() },
        findIdentityByEmail: (e) => storage.identities.findByEmail(e, {}),
      }),
    process.env.GOOGLE_CLIENT_ID &&
      google<DemoProfile>({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: `${BASE_URL}/auth/providers/google/callback`,
        stateSigningSecret: STATE,
      }),
    process.env.GITHUB_CLIENT_ID &&
      github<DemoProfile>({
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        redirectUri: `${BASE_URL}/auth/providers/github/callback`,
        stateSigningSecret: STATE,
      }),
    () =>
      passkey<DemoProfile>({
        expectedOrigins: BASE_URL,
        findIdentityByEmail: (e) => storage.identities.findByEmail(e, {}),
        rpID: 'localhost',
        rpName: 'duck-auth-demo',
      }),
  ],
  storage,
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})
