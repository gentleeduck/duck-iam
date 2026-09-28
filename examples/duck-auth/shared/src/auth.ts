import { drizzlePgAdapter } from '@gentleduck/auth/adapters/drizzle/pg'
import { AuthError, createAuth, type Deliver, orNull, type Provider } from '@gentleduck/auth/core'
import { cookieTransport, memoryDPoPNonceStore, type Transport } from '@gentleduck/auth/core/transport'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { magicLink } from '@gentleduck/auth/providers/magic-link'
import { mfaProvider } from '@gentleduck/auth/providers/mfa'
import type { OAuth } from '@gentleduck/auth/providers/oauth/core'
import { github } from '@gentleduck/auth/providers/oauth/github'
import { google } from '@gentleduck/auth/providers/oauth/google'
import { passwords } from '@gentleduck/auth/providers/passwords'
import type { AppDb } from './db'

/** The client app every emailed link opens; its page posts the token back to the backend. */
export const APP_URL = process.env.APP_URL ?? 'http://localhost:5100'

/** Where the client pages live, the same path in every client. */
export const PAGES = {
  magicLink: '/magic-link',
  resetPassword: '/reset-password',
  signIn: '/sign-in',
  verifyEmail: '/verify-email',
}

/** Where the browser lands after an IdP callback: the app once signed in, the sign-in page with the code otherwise. */
export async function landing(callback: Promise<Provider.Intent[]>): Promise<Provider.Intent[]> {
  const failedWith = (code: string) => `${APP_URL}${PAGES.signIn}?error=${code}`
  try {
    const intents = await callback
    const failed = intents.find((intent) => intent.type === 'error')
    const url = failed ? failedWith(failed.code) : APP_URL
    return [...intents.filter((intent) => intent.type !== 'error'), { type: 'redirect', url }]
  } catch (err) {
    if (!(err instanceof AuthError)) throw err
    return [{ type: 'redirect', url: failedWith(err.code) }]
  }
}

/** No mailer in an example: every token link is printed where the backend runs. */
const deliver: Deliver = async ({ identity, kind, vars }) => {
  console.log(`\n[${kind}] ${identity.profile.email}\n  ${vars.url}\n`)
}

/** http, so neither cookie can carry `Secure`; the CSRF companion is then `duck-csrf`. */
const cookies = cookieTransport({ name: 'duck-sid', secure: false })

// OAuth turns on per provider once its client id and secret are both set. `API_URL` is this backend's public
// `/auth` parent, which the IdP must have registered as the redirect target.
const oauth = {
  nonceStore: memoryDPoPNonceStore(),
  // Links an IdP sign-in to an existing account only when both sides verified the address.
  onFederationConflict: 'link-if-verified',
  // A first-time IdP user becomes an account under the address the IdP returned; no address, no account.
  profileToIdentityProfile: ({ email, name }) => (email ? { email, name: name ?? email, username: email } : null),
  stateCookie: { name: 'duck-oauth', secure: false },
  stateSigningSecret: process.env.OAUTH_STATE_SECRET ?? 'examples-only-oauth-state-secret-32ch',
} satisfies Partial<OAuth.OptionsBase>
const redirectUri = (id: string) => `${process.env.API_URL}/auth/providers/oauth:${id}/callback`

export function buildAuth(db: AppDb, transport: Transport.ITransport = cookies) {
  const stores = drizzlePgAdapter(db)
  return createAuth({
    baseUrl: APP_URL,
    deliver,
    // Ten tries per account and flow every 15 minutes, counted in this process only.
    limiter: new MemoryLimiter(),
    stores,
    transport,
    providers: [
      passwords(),
      mfaProvider({ issuer: 'duck-auth examples' }),
      (_engine, send) =>
        magicLink({
          callbackPath: PAGES.magicLink,
          deliver: send,
          findIdentityByEmail: (email) => orNull(stores.identities.find({ email })),
        }),
      process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET
        ? github({
            ...oauth,
            clientId: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            redirectUri: redirectUri('github'),
          })
        : null,
      process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
        ? google({
            ...oauth,
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            redirectUri: redirectUri('google'),
          })
        : null,
    ],
  })
}

export type AppAuth = ReturnType<typeof buildAuth>
