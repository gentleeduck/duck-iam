import { AuthError, type Provider } from '@gentleduck/auth/core'
import type { AppAuth } from './auth'
import { readString } from './body'

/** The signed-in caller. Refuses a guest, and a session still at one factor once TOTP is enrolled. */
export async function signedIn(auth: AppAuth, headers: Headers) {
  const resolved = await auth.resolveSession({ headers }).orNull()
  if (!resolved?.identity) throw new AuthError('AUTH_UNAUTHENTICATED')
  const totp = await auth.mfa.hasTotp(resolved.identity.id)
  if (totp && resolved.session.aal < 2) {
    throw new AuthError('AUTH_STEP_UP_REQUIRED', { challenge: { methods: ['totp', 'backup-code'] } })
  }
  return { session: resolved.session, identity: resolved.identity, totp }
}

/** The second step of a sign-in: a TOTP code or a backup code lifts the session to AAL 2. Answers the intents
 *  that set the new session's cookies. */
export async function stepUp(
  auth: AppAuth,
  headers: Headers,
  body: unknown,
  caller: { ip?: string; userAgent?: string },
): Promise<Provider.Intent[]> {
  const sid = auth.transport.extract({ headers })
  if (!sid) throw new AuthError('AUTH_UNAUTHENTICATED')
  const code = readString(body, 'code') ?? ''
  const { intents } = await auth.flows.completeStepUp({
    currentSid: sid,
    method: /^\d{6}$/.test(code) ? 'totp' : 'backup-code',
    code,
    ...caller,
  })
  // duck-auth keeps the one-factor session for a tab still holding it. A cookie leaves no such tab, so it goes.
  await auth.sessions.revoke(sid)
  return [...intents, { type: 'json', status: 200, body: { ok: true } }]
}
