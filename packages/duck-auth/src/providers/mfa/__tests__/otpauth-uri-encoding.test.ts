/**
 * `buildOtpAuthUri` percent-encoded `issuer` and then handed it to `URLSearchParams`, which encodes
 * again: an issuer of `Acme Corp` left as `issuer=Acme%2520Corp` and the authenticator app displayed
 * the literal `Acme%20Corp`.
 */

import { describe, expect, it } from 'vitest'
import { buildOtpAuthUri } from '../internal/totp'

const SECRET = 'JBSWY3DPEHPK3PXP'

/** What an authenticator app reads, which is the decoded value and not the raw query. */
function issuerParam(uri: string): string | null {
  return new URL(uri).searchParams.get('issuer')
}

describe('the otpauth URI says what the issuer is called', () => {
  it('an issuer with a space survives the round trip', () => {
    const uri = buildOtpAuthUri({ accountName: 'user@x.com', issuer: 'Acme Corp', secret: SECRET })

    expect(issuerParam(uri)).toBe('Acme Corp')
    expect(uri).not.toContain('%2520')
  })

  it('the issuer parameter and the label prefix agree, as the Key Uri Format requires', () => {
    const uri = buildOtpAuthUri({ accountName: 'user@x.com', issuer: 'Acme & Co', secret: SECRET })

    const label = decodeURIComponent(new URL(uri).pathname.replace(/^\/+/, ''))
    expect(label).toBe('Acme & Co:user@x.com')
    expect(issuerParam(uri)).toBe('Acme & Co')
  })

  it('a non-ascii issuer round trips too', () => {
    const uri = buildOtpAuthUri({ accountName: 'user@x.com', issuer: 'Ünïcode', secret: SECRET })

    expect(issuerParam(uri)).toBe('Ünïcode')
  })

  it('the plain case is untouched, and the rest of the parameters still read as before', () => {
    const uri = buildOtpAuthUri({ accountName: 'user@x.com', issuer: 'duck-auth', secret: SECRET })

    const params = new URL(uri).searchParams
    expect(params.get('issuer')).toBe('duck-auth')
    expect(params.get('secret')).toBe(SECRET)
    expect(params.get('algorithm')).toBe('SHA1')
    expect(params.get('digits')).toBe('6')
    expect(params.get('period')).toBe('30')
  })
})
