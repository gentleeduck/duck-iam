/**
 * The Live stories' calls to the demo backend at `:8787`: plain `fetch` with the cookie session, and the CSRF
 * token read back from its cookie.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

const BACKEND = 'http://localhost:8787'

/** `value[key]` when `value` is an object, else `undefined`. */
function pick(value: unknown, key: string): unknown {
  return typeof value === 'object' && value !== null ? Reflect.get(value, key) : undefined
}

async function call(path: string, body?: unknown): Promise<{ ok: boolean; data: unknown }> {
  const csrf = document.cookie
    .split('; ')
    .find((entry) => entry.startsWith('duck-csrf='))
    ?.slice('duck-csrf='.length)
  const res = await fetch(`${BACKEND}${path}`, {
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...(csrf && { 'x-csrf-token': decodeURIComponent(csrf) }) },
    method: body === undefined ? 'GET' : 'POST',
  })
  return { data: await res.json().catch(() => null), ok: res.ok }
}

export const live = {
  signIn: async (email: string, password: string): Promise<{ ok: true } | { ok: false; message: string }> => {
    const res = await call('/auth/signin', { input: { email, password }, providerId: 'password' })
    const code = pick(pick(res.data, 'error'), 'code')
    return res.ok ? { ok: true } : { message: typeof code === 'string' ? code : 'Sign-in failed.', ok: false }
  },
  signOut: async (): Promise<void> => {
    await call('/auth/signout', {})
  },
  /** The signed-in identity's email, or `null` for a guest. */
  session: async (): Promise<string | null> => {
    const email = pick(pick(pick((await call('/auth/session')).data, 'identity'), 'profile'), 'email')
    return typeof email === 'string' ? email : null
  },
  /** A redirect provider answers `{ url }`, and the page is sent there. */
  begin: async (provider: { id: string; input?: unknown }): Promise<void> => {
    const res = await call(`/auth/providers/${encodeURIComponent(provider.id)}/begin`, provider.input ?? {})
    const url = pick(res.data, 'url')
    if (typeof url === 'string') location.assign(url)
  },
}
