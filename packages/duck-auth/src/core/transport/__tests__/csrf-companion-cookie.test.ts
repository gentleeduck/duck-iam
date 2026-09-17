/**
 * The CSRF companion cookie is useful only if the page that must read it is in scope for it, and every
 * attribute deciding that was hardcoded while the session cookie beside it took the operator's config.
 *
 * Measured before the fix, with `{ domain: '.example.com' }` — the option that exists for cross-subdomain
 * deployments, and the one the constructor's `__Host-` checks validate: the session cookie went out for
 * the whole domain and the companion as `__Host-duck-csrf` for the issuing host alone. A page on any
 * sibling subdomain could not read the token, could not put it on `x-csrf-token`, and had every
 * state-changing request refused `AUTH_CSRF` with nothing said. `sameSite: 'none'` and `path` diverged the
 * same way, the latter leaving the token readable at `/` while the session was scoped below it.
 */
import { describe, expect, it } from 'vitest'
import type { Sessions } from '~/core/sessions/sessions.types'
import { type CookieTransport, cookieTransport } from '../cookie.transport'

const session = { expiresAt: new Date(Date.now() + 600_000) } as Sessions.Me

type Cookie = { name: string; options: Record<string, unknown>; value?: string }

function cookies(cfg: CookieTransport.Cfg): { sid: Cookie; csrf: Cookie } {
  const t = cookieTransport(cfg)
  const [sid, csrf] = t.issue('the-sid', session, {
    absolute: false,
    csrfToken: 'the-token',
    fresh: true,
  }) as unknown as Cookie[]
  if (!sid || !csrf) throw new Error('issue() emitted no companion')
  return { csrf, sid }
}

/** Every config the transport documents, plus the defaults. */
const CONFIGS: Array<[string, CookieTransport.Cfg]> = [
  ['defaults', {}],
  ['a cross-subdomain domain', { domain: '.example.com' }],
  ['sameSite none, for a cross-site SPA', { sameSite: 'none' }],
  ['a scoped path', { name: 'duck-sid', path: '/app' }],
  ['plain http for local dev', { name: 'duck-sid', secure: false }],
  ['all of them at once', { domain: '.example.com', name: 'sid', path: '/app', sameSite: 'none', secure: false }],
]

describe('the CSRF companion is scoped to the session cookie', () => {
  it.each(CONFIGS)('%s: the two agree on everything but httpOnly', (_label, cfg) => {
    const { csrf, sid } = cookies(cfg)
    expect(sid.options.httpOnly).toBe(true)
    expect(csrf.options.httpOnly).toBe(false)
    for (const attr of ['domain', 'path', 'sameSite', 'secure', 'maxAge']) {
      expect({ [attr]: csrf.options[attr] }).toEqual({ [attr]: sid.options[attr] })
    }
  })

  it.each(CONFIGS)('%s: the __Host- prefix is there exactly when the cookie satisfies it', (_label, cfg) => {
    const { csrf } = cookies(cfg)
    const satisfiable = csrf.options.secure === true && csrf.options.path === '/' && csrf.options.domain === undefined
    expect(csrf.name).toBe(satisfiable ? '__Host-duck-csrf' : 'duck-csrf')
  })

  it('keeps the documented default name and value', () => {
    const { csrf } = cookies({})
    expect(csrf.name).toBe('__Host-duck-csrf')
    expect(csrf.value).toBe('the-token')
    expect(csrf.options).toMatchObject({ httpOnly: false, path: '/', sameSite: 'lax', secure: true })
  })

  it('a sibling subdomain is in scope for the token under a domain config', () => {
    const { csrf, sid } = cookies({ domain: '.example.com' })
    expect(csrf.options.domain).toBe('.example.com')
    expect(csrf.name).toBe('duck-csrf')
    expect(sid.name).toBe('duck-sid')
  })

  it('survives plain http instead of being dropped by a prefix it cannot satisfy', () => {
    const { csrf } = cookies({ name: 'duck-sid', secure: false })
    expect(csrf.name).toBe('duck-csrf')
    expect(csrf.options.secure).toBe(false)
  })

  it('csrfCookieName is what issue() emits, for the client to read it back by', () => {
    for (const [, cfg] of CONFIGS) {
      expect(cookieTransport(cfg).csrfCookieName).toBe(cookies(cfg).csrf.name)
    }
  })

  it.each(CONFIGS)('%s: revoke clears both under the attributes they were set with', (_label, cfg) => {
    const issued = cookies(cfg)
    const [sid, csrf] = cookieTransport(cfg).revoke() as unknown as Cookie[]
    expect(sid?.name).toBe(issued.sid.name)
    expect(csrf?.name).toBe(issued.csrf.name)
    for (const attr of ['domain', 'path', 'sameSite', 'secure']) {
      expect({ [attr]: csrf?.options[attr] }).toEqual({ [attr]: issued.csrf.options[attr] })
    }
    expect(csrf?.options.maxAge).toBe(0)
  })
})
