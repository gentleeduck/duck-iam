import { AuthError, type Flows, type Provider } from '@gentleduck/auth/core'
import { parseCookie } from '@gentleduck/auth/core/transport'
import type { AppAuth } from './auth'
import { readString } from './body'

/** Where a sign-in stopped at its second factor keeps the challenge until `/mfa` answers it. */
const CHALLENGE = 'duck-mfa'
const CHALLENGE_COOKIE = { httpOnly: true, path: '/', sameSite: 'lax', secure: false } satisfies Provider.CookieOptions
const STEP_UP = { challenge: { methods: ['totp', 'backup-code'] } }

/** Holds a sign-in's challenge for the `/mfa` step, or clears one when there is none. */
export function holdChallenge(challenge: Flows.SignInChallenge | null): Provider.Intent {
  return challenge
    ? {
        type: 'setCookie',
        name: CHALLENGE,
        value: challenge.token,
        options: { ...CHALLENGE_COOKIE, expires: challenge.expiresAt },
      }
    : { type: 'clearCookie', name: CHALLENGE, options: { ...CHALLENGE_COOKIE, maxAge: 0 } }
}

/** The signed-in caller. Refuses a guest, and a session still at one factor once TOTP is enrolled; a sign-in
 *  stopped at its second factor holds no session yet, only the challenge `/mfa` answers. */
export async function signedIn(auth: AppAuth, headers: Headers) {
  const resolved = await auth.resolveSession({ headers }).orNull()
  if (!resolved?.identity) {
    throw parseCookie(headers.get('cookie') ?? '', CHALLENGE)
      ? new AuthError('AUTH_STEP_UP_REQUIRED', STEP_UP)
      : new AuthError('AUTH_UNAUTHENTICATED')
  }
  const totp = await auth.mfa.hasTotp(resolved.identity.id)
  if (totp && resolved.session.aal < 2) throw new AuthError('AUTH_STEP_UP_REQUIRED', STEP_UP)
  return { session: resolved.session, identity: resolved.identity, totp }
}

/** The second step of a sign-in: a TOTP code or a backup code answers the challenge it stopped at, or lifts a
 *  session signed in before TOTP was enrolled to AAL 2. Answers the intents that set the session's cookies. */
export async function stepUp(
  auth: AppAuth,
  headers: Headers,
  body: unknown,
  caller: { ip?: string; userAgent?: string },
): Promise<Provider.Intent[]> {
  const code = readString(body, 'code') ?? ''
  const method = /^\d{6}$/.test(code) ? 'totp' : 'backup-code'
  const sid = auth.transport.extract({ headers })
  const challenge = parseCookie(headers.get('cookie') ?? '', CHALLENGE)
  if (challenge) {
    const { intents } = await auth.flows.completeStepUp({
      challenge,
      code,
      method,
      previousSid: sid ?? undefined,
      ...caller,
    })
    return [...intents, holdChallenge(null), { type: 'json', status: 200, body: { ok: true } }]
  }
  if (!sid) throw new AuthError('AUTH_UNAUTHENTICATED')
  const { intents } = await auth.flows.completeStepUp({ currentSid: sid, code, method, ...caller })
  // duck-auth keeps the one-factor session for a tab still holding it. A cookie leaves no such tab, so it goes.
  await auth.sessions.revoke(sid)
  return [...intents, { type: 'json', status: 200, body: { ok: true } }]
}
