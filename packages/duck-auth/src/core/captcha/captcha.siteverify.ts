/** The siteverify call the three providers share: a form-encoded `secret` + `response` POST, answered
 *  with `success`, `error-codes`, `hostname` and `challenge_ts`. */

import { AuthError } from '../errors'
import { isFiniteNumber, isRecord } from '../predicates'
import { assertSafeOutboundUrl } from '../url-validators'
import {
  CAPTCHA_FORWARD_SKEW_MS,
  CAPTCHA_MAX_AGE_DEFAULT_MS,
  CAPTCHA_TIMEOUT_DEFAULT_MS,
  CAPTCHA_TIMEOUT_MAX_MS,
  CAPTCHA_TOKEN_MAX_LENGTH,
} from './captcha.constants'
import type { AuthCaptcha } from './captcha.types'

/** A siteverify body, with the wire's `error-codes` and `challenge_ts` renamed and everything a
 *  provider does not send left off. */
export interface SiteVerifyResponse {
  success: boolean
  errorCodes?: string[]
  hostname?: string
  challengeTs?: string
  /** reCAPTCHA v3 only; {@link parseSiteVerifyBasic} never sets it. */
  score?: number
  action?: string
}

/** A verifier's base options, defaulted and validated once at construction. */
export interface ResolvedCaptchaCfg {
  secret: string
  fetch: typeof globalThis.fetch
  endpoint: string
  timeoutMs: number
  /** Lowercased, and `null` when the hostname is reported but not checked. */
  expectedHostnames: string[] | null
  expectedAction: string | undefined
  maxChallengeAgeMs: number
}

/** `expectedAction` is not on `ICfgBase`: only the providers that echo an action accept one. */
export function resolveCaptchaCfg(
  cfg: AuthCaptcha.ICfgBase & { expectedAction?: string },
  verifier: string,
  endpoint: string,
): ResolvedCaptchaCfg {
  if (!cfg.secret) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `${verifier} requires a \`secret\`` })
  }
  const resolvedEndpoint = cfg.endpoint ?? endpoint
  // The secret is posted here, so it gets the guard every other outbound URL does.
  assertSafeOutboundUrl(resolvedEndpoint, {
    allowInsecure: cfg.allowInsecureEndpoint ?? false,
    label: `${verifier} endpoint`,
  })
  const timeoutMs = cfg.timeoutMs ?? CAPTCHA_TIMEOUT_DEFAULT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > CAPTCHA_TIMEOUT_MAX_MS) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${verifier} timeoutMs must be a positive number up to ${CAPTCHA_TIMEOUT_MAX_MS}`,
    })
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
  if (cfg.expectedAction !== undefined && (typeof cfg.expectedAction !== 'string' || cfg.expectedAction.length === 0)) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `${verifier} expectedAction must be a non-empty string` })
  }
  return {
    // Canonical, so the verifiers' `startsWith('http:')` also catches `HTTP://` and a leading space.
    endpoint: new URL(resolvedEndpoint).href,
    expectedAction: cfg.expectedAction,
    expectedHostnames: hosts?.map((h) => h.toLowerCase()) ?? null,
    fetch: cfg.fetch ?? globalThis.fetch,
    maxChallengeAgeMs,
    secret: cfg.secret,
    timeoutMs,
  }
}

/** A body that passed every shared check, or the failed result to hand straight back. */
export type SiteVerifyOutcome =
  | { ok: true; parsed: SiteVerifyResponse }
  | { ok: false; result: AuthCaptcha.IVerifyResult }

/** POST the token and run the checks every provider shares. */
export async function siteVerify(
  cfg: ResolvedCaptchaCfg,
  input: AuthCaptcha.IVerifyInput,
  parse: (raw: unknown) => SiteVerifyResponse | null,
): Promise<SiteVerifyOutcome> {
  if (!input.token) return fail(['missing-input-response'])
  // A parsed body can hand over an array, whose `.length` counts elements and so slips the cap.
  if (typeof input.token !== 'string') return fail(['invalid-input-response'])
  if (input.token.length > CAPTCHA_TOKEN_MAX_LENGTH) return fail(['invalid-input-response', 'token-too-large'])
  // SECURITY: `''` would match the `''` a response without a hostname falls back to, turning the check off.
  const host = input.expectedHostname
  if (host !== undefined && (typeof host !== 'string' || host.length === 0)) return fail(['invalid-expected-hostname'])
  // SECURITY: `''` would replace the configured action and match a widget mounted without one.
  if (input.expectedAction === '') return fail(['invalid-expected-action'])

  const body = new URLSearchParams({
    secret: cfg.secret,
    response: input.token,
    ...(input.remoteIp ? { remoteip: input.remoteIp } : null),
  })
  // Armed over the body read too: `fetch` settles on the headers.
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), cfg.timeoutMs)
  let text: string
  try {
    const res = await cfg.fetch(cfg.endpoint, {
      method: 'POST',
      body: body.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      // SECURITY: `assertSafeOutboundUrl` vetted `cfg.endpoint`, not a redirect target, and a 307 would
      // re-post this body with the secret in it.
      redirect: 'error',
      signal: abort.signal,
    })
    // A non-2xx is not a solved challenge, however well its body parses.
    if (!res.ok) return fail([`provider-http-${res.status}`])
    // As text, so a body the socket dropped fails here as the network's, and only one that is not JSON
    // reaches `parse` as malformed.
    text = await res.text()
  } catch (err) {
    if (abort.signal.aborted) return fail(['timeout'])
    return fail(['network-error'], err instanceof Error ? err.message : String(err))
  } finally {
    clearTimeout(timer)
  }

  const parsed = parse(parseJsonOrNull(text))
  if (!parsed) return fail(['malformed-response'])

  // Every refusal below still reports what the provider sent, so the caller can apply its own rule.
  const carried = toResult(parsed, false)
  const refuse = (code: string): SiteVerifyOutcome => ({
    ok: false,
    result: { ...carried, errorCodes: [...(carried.errorCodes ?? []), code] },
  })

  // Case-insensitive, as a hostname is (RFC 4343).
  const expected = host !== undefined ? [host.toLowerCase()] : cfg.expectedHostnames
  if (expected !== null && !expected.includes((parsed.hostname ?? '').toLowerCase())) return refuse('hostname-mismatch')
  // Turnstile and reCAPTCHA v3 both echo the widget's action; a wrong one, or none, fails.
  const action = input.expectedAction ?? cfg.expectedAction
  if (action !== undefined && parsed.action !== action) return refuse('action-mismatch')
  const aged = challengeAgeRefusal(parsed.challengeTs, cfg.maxChallengeAgeMs)
  if (aged !== null) return refuse(aged)
  // A rejection always names a code: `errorCodes` is all a caller has to log.
  if (!parsed.success && !parsed.errorCodes?.length) parsed.errorCodes = ['provider-rejected']
  return { ok: true, parsed }
}

/** The provider's own fields, carried through for a caller applying its own rule. */
export function toResult(parsed: SiteVerifyResponse, success: boolean): AuthCaptcha.IVerifyResult {
  const out: AuthCaptcha.IVerifyResult = { success }
  if (parsed.score !== undefined) out.score = parsed.score
  if (parsed.errorCodes !== undefined) out.errorCodes = parsed.errorCodes
  if (parsed.hostname !== undefined) out.hostname = parsed.hostname
  if (parsed.action !== undefined) out.action = parsed.action
  if (parsed.challengeTs !== undefined) out.challengeTs = parsed.challengeTs
  return out
}

/** A failure with nothing parsed behind it. */
function fail(errorCodes: string[], detail?: string): SiteVerifyOutcome {
  return { ok: false, result: { errorCodes, success: false, ...(detail !== undefined && { detail }) } }
}

/** The code for a `challenge_ts` too old or too far ahead; `null` when fine, or absent, since a provider
 *  that sends none cannot be aged. */
function challengeAgeRefusal(challengeTs: string | undefined, maxAgeMs: number): string | null {
  if (maxAgeMs === 0 || challengeTs === undefined) return null
  const at = Date.parse(challengeTs)
  if (Number.isNaN(at)) return 'malformed-challenge-ts'
  const age = Date.now() - at
  if (age > maxAgeMs) return 'challenge-expired'
  return age < -CAPTCHA_FORWARD_SKEW_MS ? 'challenge-in-future' : null
}

/** The body as JSON, or `null` when it is not JSON. */
function parseJsonOrNull(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** `undefined` when absent, `null` when not a list of strings. */
function parseErrorCodes(raw: unknown): string[] | null | undefined {
  if (raw === undefined || raw === null) return undefined
  if (!Array.isArray(raw)) return null
  const out: string[] = []
  for (const c of raw) {
    if (typeof c !== 'string') return null
    out.push(c)
  }
  return out
}

/** The fields Turnstile and hCaptcha share. `null` for anything that is not a siteverify body, which
 *  the caller reports as `malformed-response` rather than as a failed challenge. */
export function parseSiteVerifyBasic(raw: unknown): SiteVerifyResponse | null {
  if (!isRecord(raw)) return null
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
  if (raw.action !== undefined) {
    if (typeof raw.action !== 'string') return null
    out.action = raw.action
  }
  return out
}

/** {@link parseSiteVerifyBasic} plus reCAPTCHA v3's `score`. A score that is not a finite number makes
 *  the whole body malformed, rather than a pass with the score quietly dropped. */
export function parseSiteVerifyRecaptchaV3(raw: unknown): SiteVerifyResponse | null {
  const base = parseSiteVerifyBasic(raw)
  if (!base || !isRecord(raw)) return null
  if (raw.score !== undefined) {
    if (!isFiniteNumber(raw.score)) return null
    base.score = raw.score
  }
  return base
}
