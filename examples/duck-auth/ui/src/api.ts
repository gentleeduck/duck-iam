import { renderSVG } from 'uqr'
import { BACKENDS, type Backend } from './backends'

export { BACKENDS, type Backend }

/** A backend's answer: the data on success, its error envelope otherwise. */
export type Envelope<T> =
  | { ok: true; code: string; data: T }
  | { ok: false; error: { code: string; status?: number } & Record<string, unknown> }

export type Provider = { id: string; kind: string }

export type Account = {
  identity: { id: string; emailVerified: boolean; profile: { email: string; name: string } }
  totp: boolean
  session: { id: string; aal: number; expiresAt: string }
}

/** A signed-in device, as `/me/sessions` lists it. */
export type Session = { id: string; createdAt: string; ip: string | null }

const PICKED = 'duck-auth-backend'

function isBackend(name: string | null): name is Backend {
  return name !== null && Object.hasOwn(BACKENDS, name)
}

/** The backend this browser talks to, kept across reloads; express until another is picked. */
export function pickedBackend(): Backend {
  const saved = localStorage.getItem(PICKED)
  return isBackend(saved) ? saved : 'express'
}

export function pickBackend(name: string): void {
  if (isBackend(name)) localStorage.setItem(PICKED, name)
  location.reload()
}

const MESSAGES: Record<string, string> = {
  AUTH_CSRF: 'The page went stale. Reload it and try again.',
  AUTH_EMAIL_TAKEN: 'An account already uses that email.',
  AUTH_HTTP_ERROR: 'The backend is not answering. Is it running?',
  AUTH_INVALID_CREDENTIALS: 'That did not match. Check it and try again.',
  AUTH_INVALID_PARAMETERS: 'Something in the form is missing or not valid.',
  AUTH_MISCONFIGURED: 'The backend is misconfigured. Its terminal says how.',
  AUTH_NETWORK_ERROR: 'The backend is not answering. Is it running?',
  AUTH_OAUTH_NONCE_REPLAY: 'That sign-in was already used. Start it again.',
  AUTH_OAUTH_STATE_MISMATCH: 'That sign-in expired or began in another browser. Start it again.',
  AUTH_PROVIDER_FAILED: 'The provider could not sign you in. If you already have an account, verify its email first.',
  AUTH_RATE_LIMITED: 'Too many attempts. Wait a while and try again.',
  AUTH_RECOVERY_REQUIRES_MFA:
    'This account has two-factor authentication. Sign in with an email link and your code, then open this link again.',
  AUTH_RECOVERY_TOKEN_EXPIRED: 'This link has expired. Ask for a new one.',
  AUTH_RECOVERY_TOKEN_INVALID: 'This link is not valid. It may have been used already.',
  AUTH_UNAUTHENTICATED: 'You are signed out.',
}

export const WEAK_PASSWORD = 'Pick a stronger password: at least 8 characters, and not a common one.'

/** A failure envelope as a sentence for the page. `invalid` rewords a refused input where a page knows why. */
export function errorText(res: Envelope<unknown>, invalid = MESSAGES.AUTH_INVALID_CREDENTIALS): string {
  if (res.ok) return ''
  const { code, retryAfter } = res.error
  if (code === 'AUTH_RATE_LIMITED' && typeof retryAfter === 'number') {
    const minutes = Math.ceil(retryAfter / 60)
    return `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`
  }
  return code === 'AUTH_INVALID_CREDENTIALS' ? invalid : (MESSAGES[code] ?? `Something went wrong (${code}).`)
}

/** A failure handed over in the URL, as the sign-in page's `?error=CODE`, as the envelope its notice shows. */
export function landedWith(code: string | null | undefined): Envelope<unknown> | null {
  return code ? { ok: false, error: { code } } : null
}

/** Where a page that needs a signed-in user sends a caller the backend refused. */
export function leaveTo(code: string): string {
  if (code === 'AUTH_STEP_UP_REQUIRED') return '/mfa'
  return code === 'AUTH_UNAUTHENTICATED' ? '/sign-in' : `/sign-in?error=${code}`
}

/** A listed session as one line: when it signed in, and from where. */
export function sessionLine(session: Session): string {
  const at = new Date(session.createdAt).toLocaleString()
  return session.ip ? `Signed in ${at} from ${session.ip}` : `Signed in ${at}`
}

/** A TOTP setup's `otpauth://` URI as a scannable QR code, quiet zone included, for an `<img>` source. */
export function qrCode(uri: string): string {
  return `data:image/svg+xml,${encodeURIComponent(renderSVG(uri, { border: 4 }))}`
}

/** The routes each backend example mounts, answered as an {@link Envelope}. */
export function createApi(base: string) {
  async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Envelope<T>> {
    const csrf = document.cookie
      .split('; ')
      .find((entry) => entry.startsWith('duck-csrf='))
      ?.slice('duck-csrf='.length)
    const res = await fetch(`${base}${path}`, {
      method,
      credentials: 'include',
      headers: {
        ...(body !== undefined && { 'content-type': 'application/json' }),
        ...(csrf && { 'x-csrf-token': decodeURIComponent(csrf) }),
      },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    }).catch(() => null)
    if (!res) return { ok: false, error: { code: 'AUTH_NETWORK_ERROR' } }
    const data = await res.json().catch(() => null)
    if (res.ok) return { ok: true, code: 'AUTH_OK', data }
    const error = data?.error ?? { code: 'AUTH_HTTP_ERROR', status: res.status }
    // Signed out from another device: a page that needs the session starts again at sign-in.
    if (error.code === 'AUTH_UNAUTHENTICATED') location.assign('/sign-in')
    return { ok: false, error }
  }

  return {
    signIn: (providerId: string, input: unknown) => call('POST', '/auth/signin', { providerId, input }),
    signUp: (input: { email: unknown; name: unknown; password: unknown }) => call('POST', '/auth/signup', input),
    signOut: () => call('POST', '/auth/signout'),
    /** A redirect flow answers `{ url }` and the page is sent there; the others answer their own body. */
    beginProvider: async (id: string, input: unknown = {}) => {
      const res = await call<unknown>('POST', `/auth/providers/${encodeURIComponent(id)}/begin`, input)
      const data = res.ok ? res.data : null
      if (typeof data === 'object' && data !== null && 'url' in data && typeof data.url === 'string') {
        location.assign(data.url)
      }
      return res
    },
    providers: () => call<{ providers: Provider[] }>('GET', '/auth/providers'),
    forgotPassword: (email: string) => call('POST', '/auth/password/forgot', { email }),
    resetPassword: (token: string, password: string) => call('POST', '/auth/password/reset', { token, password }),
    verifyEmail: (token: string) => call('POST', '/auth/email/verify', { token }),
    verifyMfa: (code: string) => call('POST', '/auth/mfa/verify', { code }),
    beginTotp: () => call<{ secret: string; uri: string }>('POST', '/auth/mfa/totp/begin'),
    confirmTotp: (code: string) => call<{ backupCodes: string[] }>('POST', '/auth/mfa/totp/confirm', { code }),
    removeTotp: () => call('POST', '/auth/mfa/totp/remove'),
    newBackupCodes: () => call<{ backupCodes: string[] }>('POST', '/auth/mfa/backup-codes'),
    account: () => call<Account>('GET', '/me'),
    resendVerification: () => call('POST', '/me/email/resend'),
    /** Every signed-in device, newest first: the store keeps no order. */
    sessions: async () => {
      const res = await call<{ sessions: Session[] }>('GET', '/me/sessions')
      if (res.ok) res.data.sessions.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      return res
    },
    signOutOthers: () => call<{ revoked: number }>('POST', '/me/sessions/revoke-others'),
  }
}

export type Api = ReturnType<typeof createApi>
