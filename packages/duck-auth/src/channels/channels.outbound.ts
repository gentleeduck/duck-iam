/** Validation for everything a delivery channel is about to hand a provider. */

import { AuthError } from '~/core/errors'
import { getProfileString } from '~/core/predicates/predicates'

/** RFC 5321: a forward-path is at most 256 octets including the angle brackets. */
const EMAIL_MAX_LENGTH = 254
const EMAIL_LOCAL_MAX_LENGTH = 64
const EMAIL_DOMAIN_MAX_LENGTH = 255
/** RFC 5322 caps a header line at 998 octets. */
export const SUBJECT_MAX_LENGTH = 998
/** One Twilio request carries at most 1600 characters, concatenated segments included. */
export const SMS_BODY_MAX_LENGTH = 1600

// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
const CONTROL_OR_SPACE = /[\u0000-\u0020\u007f]/
/** A separator a provider might split on, or a character that changes what a header means. */
const ADDRESS_SEPARATOR = /[,;<>"()[\]\\]/

export type Recipient = { ok: true; to: string } | { ok: false; error: string }

export function resolveEmailRecipient(profile: unknown, channel: string): Recipient {
  const raw = getProfileString(profile, 'email')
  if (!raw) return { error: `identity has no email; ${channel} cannot deliver`, ok: false }
  const bad = (why: string): Recipient => ({ error: `${channel}: refusing email recipient, ${why}`, ok: false })

  if (raw.length > EMAIL_MAX_LENGTH) return bad(`it is longer than ${EMAIL_MAX_LENGTH} characters`)
  // CR and LF are what turn one recipient into a second header; the rest cannot appear unquoted.
  if (CONTROL_OR_SPACE.test(raw)) return bad('it contains whitespace or a control character')
  if (ADDRESS_SEPARATOR.test(raw)) return bad('it contains an address separator or quoting character')

  const at = raw.lastIndexOf('@')
  if (at <= 0 || at === raw.length - 1) return bad('it is not local@domain')
  if (raw.indexOf('@') !== at) return bad('it carries more than one @')

  const local = raw.slice(0, at)
  const domain = raw.slice(at + 1)
  if (local.length > EMAIL_LOCAL_MAX_LENGTH) return bad(`its local part is over ${EMAIL_LOCAL_MAX_LENGTH} characters`)
  if (domain.length > EMAIL_DOMAIN_MAX_LENGTH) return bad(`its domain is over ${EMAIL_DOMAIN_MAX_LENGTH} characters`)
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return bad('its domain is malformed')

  // Non-ASCII is left alone rather than refused, so an SMTPUTF8 deployment keeps working.
  return { ok: true, to: raw }
}

/** E.164, which is the only form a `to` number may take. */
const E164 = /^\+[1-9]\d{1,14}$/

export function resolvePhoneRecipient(profile: unknown, channel: string): Recipient {
  const raw = getProfileString(profile, 'phone')
  if (!raw) return { error: `identity has no phone; ${channel} cannot deliver`, ok: false }
  if (!E164.test(raw)) return { error: `${channel}: refusing phone recipient, it is not E.164`, ok: false }
  return { ok: true, to: raw }
}

/**
 * A subject is a header value, so CR and LF cannot survive in it whatever the template did.
 * Folded to a space rather than refused: a subject is cosmetic, and dropping a whole sign-in mail
 * because a template interpolated a newline would be the worse failure.
 */
export function sanitizeSubject(subject: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point.
  return subject.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, SUBJECT_MAX_LENGTH)
}

/** What a template resolver returned, checked before it is sent rather than after. */
export function checkRenderedEmail(resolved: { subject?: unknown; text?: unknown; html?: unknown }): string | null {
  if (typeof resolved.subject !== 'string') return 'template resolver returned no string subject'
  const hasText = typeof resolved.text === 'string' && resolved.text.length > 0
  const hasHtml = typeof resolved.html === 'string' && resolved.html.length > 0
  if (!hasText && !hasHtml) return 'template resolver returned neither a text nor an html body'
  return null
}

export function checkRenderedSms(resolved: { body?: unknown }): string | null {
  if (typeof resolved.body !== 'string' || resolved.body.length === 0) {
    return 'template resolver returned no sms body'
  }
  return null
}

/**
 * What a provider said, with the parts of it that are not ours to repeat taken out.
 *
 * SECURITY: an SDK error routinely carries the request URL, the account identifier and occasionally
 * the credential that was rejected, none of which belongs in an answer to the caller.
 */
export function redactProviderError(text: string): string {
  return (
    text
      .replace(/\b([\w.-]+:\/\/[^\s?#]+)(\?[^\s]*)?/g, (_m, origin: string, query?: string) =>
        query ? `${origin}?[redacted]` : origin,
      )
      // A path segment that is one long opaque run is an account id or a credential, not a route name:
      // twilio puts its account sid in the path and telegram puts the bot token there. Route names stay,
      // so an operator still sees which call failed.
      .replace(/(?<!\/)\/[\w.:~-]{24,}(?=[/?#]|$|\s)/g, '/[redacted]')
      // The quotes are optional on both sides: an http SDK throws its response body, so the label
      // arrives as `"api_key":"..."` far more often than as `api_key=...`, and only the second matched.
      .replace(
        /([\w-]*(?:key|token|secret|password|signature|credential)[\w-]*)["']?\s*[=:]\s*["']?[^\s"',}]+["']?/gi,
        '$1=[redacted]',
      )
      // An auth scheme puts the credential one word past the label, where the pattern above stops.
      .replace(/\b(bearer|basic|digest)\s+[\w.\-+/=]+/gi, '$1 [redacted]')
  )
}

/**
 * The text to report for a failure. An `AuthError`'s `message` is its code, and everything an
 * operator needs, down to the name of the package to install, lives in `meta.detail`.
 */
export function describeSendError(err: unknown): string {
  if (err instanceof AuthError) return redactProviderError(String(err.meta.detail ?? err.code))
  return redactProviderError(err instanceof Error ? err.message : String(err))
}
