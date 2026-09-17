import { env } from 'node:process'
import { AuthError } from '../errors'
import type { AuthDefine } from './config.types'

/**
 * Every key `createAuth` honours. A `Record` and not an array, so a key added to `AuthDefine.Cfg`
 * stops compiling here until it is listed rather than joining the set of typos nobody notices.
 */
const CREATE_AUTH_KEYS: Record<keyof AuthDefine.Cfg, true> = {
  __tenantBrand: true,
  anomaly: true,
  baseUrl: true,
  captcha: true,
  channels: true,
  events: true,
  hijack: true,
  identities: true,
  idempotency: true,
  limiter: true,
  oauth: true,
  plugins: true,
  providers: true,
  resolveActor: true,
  session: true,
  stores: true,
  strict: true,
  transport: true,
}

const STRICT_ENVS = ['development', 'production', 'test'] as const

/** JSON-quoted, so a value carrying a quote or a control character cannot end the sentence reporting it. */
function describe(value: unknown): string {
  return typeof value === 'string' ? JSON.stringify(value.slice(0, 64)) : String(value)
}

/**
 * Refuse a key this factory cannot honour. `sessions` for `session` is the one a caller is most
 * likely to write, and accepting it silently leaves them believing they shortened a window.
 */
export function assertKnownKeys(config: object): void {
  const unknown = Object.keys(config).filter((key) => !Object.hasOwn(CREATE_AUTH_KEYS, key))
  if (unknown.length === 0) return
  throw new AuthError('AUTH_MISCONFIGURED', {
    detail: `createAuth does not know ${unknown.map(describe).join(', ')}; a key it cannot honour is a knob that does nothing`,
  })
}

/** Which environment's checks to run: what the caller named, else what the process is running as. */
export function resolveStrictEnv(strict: AuthDefine.Cfg['strict']): (typeof STRICT_ENVS)[number] | null {
  if (strict === false) return null
  if (strict === undefined) return STRICT_ENVS.find((name) => name === env.NODE_ENV) ?? 'development'
  const named = STRICT_ENVS.find((name) => name === strict)
  if (!named) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `strict must be one of ${STRICT_ENVS.join(', ')}, or false to opt out; got ${describe(strict)}`,
    })
  }
  return named
}

/**
 * The origin every redirect, cookie and callback URL is measured against, parsed once here rather
 * than by each facet that compares against it. The trailing slash goes because `${baseUrl}/callback`
 * is how all of them build a URL from it.
 */
export function normaliseBaseUrl(baseUrl: unknown): string {
  const parsed = parseUrl(baseUrl)
  if (!parsed || (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `baseUrl must be an absolute http(s) URL, e.g. https://app.example.com; got ${describe(baseUrl)}`,
    })
  }
  return parsed.href.endsWith('/') ? parsed.href.slice(0, -1) : parsed.href
}

function parseUrl(value: unknown): URL | null {
  if (typeof value !== 'string') return null
  try {
    return new URL(value)
  } catch {
    return null
  }
}
