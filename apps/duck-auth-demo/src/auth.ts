/**
 * Demo `AuthEngine` wired with every auth flow duck-auth ships:
 * authPassword (Argon2id), magic-link (console), OAuth (authGoogle/authGithub;
 * skipped when env keys missing), authPasskey (WebAuthn), TOTP/backup
 * codes. Storage: Postgres via the bundled Drizzle adapter.
 *
 * @author wildduck2 <https://authGithub.com/gentleeduck/duck-iam>
 */

import { authDrizzlePgStorage } from '@gentleduck/auth/adapters/drizzle/pg'
import { AuthConsoleChannel } from '@gentleduck/auth/channels/console'
import { AuthArgon2idHasher, AuthCookieTransport, defineAuth } from '@gentleduck/auth/core'
import { AuthMemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { authMagicLink } from '@gentleduck/auth/providers/magic-link'
import { authGithub } from '@gentleduck/auth/providers/oauth/github'
import { authGoogle } from '@gentleduck/auth/providers/oauth/google'
import { authPasskey } from '@gentleduck/auth/providers/passkey'
import { authPassword } from '@gentleduck/auth/providers/password'

export interface DemoProfile {
  email: string
  emailVerified: boolean
  name?: string
}

const BASE_URL = process.env.BASE_URL ?? 'http://localhost:8787'
const STATE = process.env.OAUTH_STATE_SECRET ?? 'demo-state-signing-secret-change-me-32-chars'

const storage = authDrizzlePgStorage<DemoProfile>(
  process.env.DATABASE_URL ?? 'postgres://duck:duck_dev_pw@localhost:5433/duck_auth_demo',
)

export const auth = defineAuth<DemoProfile>({
  baseUrl: BASE_URL,
  channels: { email: new AuthConsoleChannel() },
  hasher: new AuthArgon2idHasher(),
  limiter: new AuthMemoryLimiter({ max: 30, windowMs: 60_000 }),
  oauth: { stateSigningSecret: STATE },
  providers: [
    (a) =>
      authPassword<DemoProfile>({
        findIdentityByEmail: (e) => storage.identities.findByEmail(e, {}),
        passwords: a.passwords,
      }),
    () =>
      authMagicLink<DemoProfile>({
        autoCreateIdentity: true,
        autoCreateProfile: (email) => ({ email, emailVerified: false }),
        callbackPath: '/auth/magic-link/verify',
        channels: { email: new AuthConsoleChannel() },
        findIdentityByEmail: (e) => storage.identities.findByEmail(e, {}),
      }),
    process.env.GOOGLE_CLIENT_ID &&
      authGoogle<DemoProfile>({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
        redirectUri: `${BASE_URL}/auth/providers/authGoogle/callback`,
        stateSigningSecret: STATE,
      }),
    process.env.GITHUB_CLIENT_ID &&
      authGithub<DemoProfile>({
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '',
        redirectUri: `${BASE_URL}/auth/providers/authGithub/callback`,
        stateSigningSecret: STATE,
      }),
    () =>
      authPasskey<DemoProfile>({
        expectedOrigins: BASE_URL,
        findIdentityByEmail: (e) => storage.identities.findByEmail(e, {}),
        rpID: 'localhost',
        rpName: 'duck-auth-demo',
      }),
  ],
  storage,
  transport: new AuthCookieTransport({ name: 'duck-sid', secure: false }),
})
