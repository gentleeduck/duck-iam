import { describe, expect, it } from 'vitest'
import { describeSendError, redactProviderError } from '../channels.outbound'

// Not real credentials: opaque stand-ins for the redactor's own pattern, shaped to avoid
// matching any real provider's key format (GitHub's secret scanner blocked a push over this).
const SECRET = 'notarealkey_51H8xQ2KZvKuTb7mN0aOPAQUE123'
/** Real length matters: what marks a path segment as a credential rather than a route name is that it
 *  is one long opaque run. A short stand-in would pass the test without exercising the rule. */
const TELEGRAM_TOKEN = '7123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'
const TWILIO_SID = 'XX1234567890abcdef1234567890abcdef'

/**
 * The redactor's contract is that a provider SDK's error text can be repeated back without repeating
 * the credential it was rejected for. A provider decides the shape of that text, so the cases below are
 * the shapes real SDKs produce rather than the one the pattern was written against.
 */
describe('redactProviderError', () => {
  it.each([
    ['an unquoted label', `auth failed api_key=${SECRET}`],
    ['a json body, which is what an http SDK throws', `Bad request: {"api_key":"${SECRET}","to":"x"}`],
    ['a json body with spaces around the colon', `Bad request: { "token" : "${SECRET}" }`],
    ['a nested json body', `err {"data":{"client_secret":"${SECRET}"}}`],
    ['a credential in the query string', `https://api.example.com/send?api_key=${SECRET} failed`],
    ['an Authorization scheme, where the secret is a word further on', `Unauthorized: Authorization: Bearer ${SECRET}`],
  ])('does not repeat the credential back when it arrives as %s', (_label, text) => {
    expect(redactProviderError(text)).not.toContain(SECRET)
  })

  it('redacts a Basic credential, which is a password in transport clothing', () => {
    expect(redactProviderError('Authorization: Basic U0VDUkVUMTIz')).not.toContain('U0VDUkVUMTIz')
  })

  it('redacts an account id in the path, as twilio puts it', () => {
    const out = redactProviderError(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json 401`)
    expect(out).not.toContain(TWILIO_SID)
    // The route around it survives, which is the difference between redacting and blanking.
    expect(out).toContain('/Accounts/')
    expect(out).toContain('/Messages.json')
  })

  it('redacts a credential in the path, as telegram puts it, while still naming the call', () => {
    const out = redactProviderError(`POST https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage failed`)
    expect(out).not.toContain(TELEGRAM_TOKEN)
    expect(out).toContain('api.telegram.org')
    expect(out).toContain('/sendMessage')
  })

  it('leaves a long hostname alone, which the scheme slashes would otherwise drag in', () => {
    const text = 'POST https://very-long-subdomain-name-here.example.com/v1/send failed'
    expect(redactProviderError(text)).toBe(text)
  })

  it.each([
    ['a host and port', 'smtp connect ECONNREFUSED 10.0.0.5:587'],
    ['a rate limit', 'rate limited, retry after 30s'],
    ['a rejected address', 'invalid recipient address: not-an-email'],
    ['an origin with no path', 'POST https://api.resend.com failed with 422'],
  ])('leaves %s alone, since over-redacting costs the operator the diagnosis', (_label, text) => {
    expect(redactProviderError(text)).toBe(text)
  })
})

describe('describeSendError', () => {
  it('redacts what it reports for a plain Error', () => {
    expect(describeSendError(new Error(`send failed: {"api_key":"${SECRET}"}`))).not.toContain(SECRET)
  })

  it('reports a non-Error throw rather than losing it', () => {
    expect(describeSendError('provider exploded')).toBe('provider exploded')
  })
})
