/**
 * The one siteverify call the three providers share: Turnstile, hCaptcha and reCAPTCHA all take a
 * form-encoded `secret` + `response` POST and all answer with `success`, `error-codes`, `hostname` and
 * `challenge_ts`. Kept together because three copies drifted, each needing the status check, the timeout
 * and the token cap added separately.
 */

import { AuthError } from '../errors'
import { assertSafeOutboundUrl } from '../url-validators'
import {
  CAPTCHA_FORWARD_SKEW_MS,
  CAPTCHA_MAX_AGE_DEFAULT_MS,
  CAPTCHA_TIMEOUT_DEFAULT_MS,
  CAPTCHA_TOKEN_MAX_LENGTH,
} from './captcha.constants'
import type { AuthCaptcha } from './captcha.types'

export interface SiteVerifyResponse {
  success: boolean
  errorCodes?: string[]
  hostname?: string
  challengeTs?: string
  score?: number
  action?: string
}

/** Config every verifier resolves its base options into once, at construction. */
export interface ResolvedCaptchaCfg {
  secret: string
  fetch: typeof globalThis.fetch
  endpoint: string
  timeoutMs: number
  expectedHostnames: string[] | null
  maxChallengeAgeMs: number
}

export function resolveCaptchaCfg(cfg: AuthCaptcha.ICfgBase, verifier: string, endpoint: string): ResolvedCaptchaCfg {
  if (!cfg.secret) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `${verifier} requires a \`secret\`` })
  }
  const resolvedEndpoint = cfg.endpoint ?? endpoint
  // The secret is posted to whatever this points at, so it gets the same guard as any other
  // outbound URL in the library rather than being the one that takes a loopback address quietly.
  assertSafeOutboundUrl(resolvedEndpoint, {
    allowInsecure: cfg.allowInsecureEndpoint ?? false,
    label: `${verifier} endpoint`,
  })
  const timeoutMs = cfg.timeoutMs ?? CAPTCHA_TIMEOUT_DEFAULT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `${verifier} timeoutMs must be a positive finite number` })
  }
  const maxChallengeAgeMs = cfg.maxChallengeAgeMs ?? CAPTCHA_MAX_AGE_DEFAULT_MS
  if (!Number.isFinite(maxChallengeAgeMs) || maxChallengeAgeMs < 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${verifier} maxChallengeAgeMs must be a non-negative finite number`,
    })
  }
  const hosts = cfg.expectedHostname === undefined ? null : [cfg.expectedHostname].flat()
  if (hosts !== null && (hosts.length === 0 || hosts.some((h) => typeof h !== 'string' || h.length === 0))) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${verifier} expectedHostname must be a non-empty host or list of hosts`,
    })
  }
  return {
    endpoint: resolvedEndpoint,
    expectedHostnames: hosts,
    fetch: cfg.fetch ?? globalThis.fetch,
    maxChallengeAgeMs,
    secret: cfg.secret,
    timeoutMs,
  }
}

export type SiteVerifyOutcome =
  | { ok: true; parsed: SiteVerifyResponse }
  | { ok: false; result: AuthCaptcha.IVerifyResult }

/** POST the token and return either the parsed body or the failed result to hand straight back. */
export async function siteVerify(
  cfg: ResolvedCaptchaCfg,
  input: AuthCaptcha.IVerifyInput,
  parse: (raw: unknown) => SiteVerifyResponse | null,
): Promise<SiteVerifyOutcome> {
  if (!input.token) return fail(['missing-input-response'])
  if (input.token.length > CAPTCHA_TOKEN_MAX_LENGTH) return fail(['invalid-input-response', 'token-too-large'])

  const body = new URLSearchParams({
    secret: cfg.secret,
    response: input.token,
    ...(input.remoteIp !== undefined && { remoteip: input.remoteIp }),
  })
  // Captcha fronts sign-in, so a provider that accepts the connection and never answers parks the
  // whole login path until something upstream gives up.
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), cfg.timeoutMs)
  let res: Response
  try {
    res = await cfg.fetch(cfg.endpoint, {
      method: 'POST',
      body: body.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      // SECURITY: `assertSafeOutboundUrl` vetted `cfg.endpoint`, not a redirect target, and a 307 would
      // re-post this body with the secret in it.
      redirect: 'error',
      signal: abort.signal,
    })
  } catch (err) {
    if (abort.signal.aborted) return fail(['timeout'])
    return fail(['network-error', err instanceof Error ? err.message : String(err)])
  } finally {
    clearTimeout(timer)
  }

  // A five hundred, a four twenty-nine, or a captive portal that happens to serialise
  // `{"success":true}` is not a solved challenge, however well its body parses.
  if (!res.ok) return fail([`provider-http-${res.status}`])

  const parsed = parse(await readJsonSafe(res))
  if (!parsed) return fail(['malformed-response'])

  const carried: AuthCaptcha.IVerifyResult = { success: false }
  if (parsed.hostname !== undefined) carried.hostname = parsed.hostname
  if (parsed.challengeTs !== undefined) carried.challengeTs = parsed.challengeTs
  if (parsed.errorCodes !== undefined) carried.errorCodes = parsed.errorCodes

  const expected = input.expectedHostname !== undefined ? [input.expectedHostname] : cfg.expectedHostnames
  if (expected !== null && !expected.includes(parsed.hostname ?? '')) {
    return { ok: false, result: { ...carried, errorCodes: [...(carried.errorCodes ?? []), 'hostname-mismatch'] } }
  }
  const aged = isChallengeTooOld(parsed.challengeTs, cfg.maxChallengeAgeMs)
  if (aged !== null) {
    return { ok: false, result: { ...carried, errorCodes: [...(carried.errorCodes ?? []), aged] } }
  }
  return { ok: true, parsed }
}

function fail(errorCodes: string[]): SiteVerifyOutcome {
  return { ok: false, result: { errorCodes, success: false } }
}

/**
 * `null` when the timestamp is acceptable or absent. A provider that sends no `challenge_ts` cannot
 * be aged, and refusing on that would break the ones that do not send it at all.
 */
function isChallengeTooOld(challengeTs: string | undefined, maxAgeMs: number): string | null {
  if (maxAgeMs === 0 || challengeTs === undefined) return null
  const at = Date.parse(challengeTs)
  if (Number.isNaN(at)) return 'malformed-challenge-ts'
  const age = Date.now() - at
  if (age > maxAgeMs) return 'challenge-expired'
  return age < -CAPTCHA_FORWARD_SKEW_MS ? 'challenge-in-future' : null
}

async function readJsonSafe(res: Response): Promise<unknown> {
  try {
    return await res.json()
  } catch {
    return null
  }
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function parseErrorCodes(raw: unknown): string[] | null | undefined {
  if (raw === undefined) return undefined
  if (!Array.isArray(raw)) return null
  const out: string[] = []
  for (const c of raw) {
    if (typeof c !== 'string') return null
    out.push(c)
  }
  return out
}

export function parseSiteVerifyBasic(raw: unknown): SiteVerifyResponse | null {
  if (!isPlainObject(raw)) return null
  if (typeof raw.success !== 'boolean') return null
  const errorCodes = parseErrorCodes(raw['error-codes'])
  if (errorCodes === null) return null
  const out: SiteVerifyResponse = { success: raw.success }
  if (errorCodes !== undefined) out.errorCodes = errorCodes
  if (raw.hostname !== undefined) {
    if (typeof raw.hostname !== 'string') return null
    out.hostname = raw.hostname
  }
  if (raw.challenge_ts !== undefined) {
    if (typeof raw.challenge_ts !== 'string') return null
    out.challengeTs = raw.challenge_ts
  }
  return out
}

export function parseSiteVerifyRecaptchaV3(raw: unknown): SiteVerifyResponse | null {
  const base = parseSiteVerifyBasic(raw)
  if (!base || !isPlainObject(raw)) return null
  if (raw.score !== undefined) {
    if (typeof raw.score !== 'number' || !Number.isFinite(raw.score)) return null
    base.score = raw.score
  }
  if (raw.action !== undefined) {
    if (typeof raw.action !== 'string') return null
    base.action = raw.action
  }
  return base
}
