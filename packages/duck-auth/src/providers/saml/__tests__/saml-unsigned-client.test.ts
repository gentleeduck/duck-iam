import { describe, expect, it, vi } from 'vitest'
import { type Saml, saml } from '../index'

/** node-saml keeps its resolved config on `.options`, which is the same window the callbackUrl check
 *  reads through. A client that exposes none is left alone. */
function makeClient(options?: Record<string, unknown>): Saml.Client {
  const client: Saml.Client = {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp.example/sso?SAMLRequest=AAA'),
    validatePostResponseAsync: vi.fn(async () => ({
      loggedOut: false,
      profile: { email: 'user@x.com', nameID: 'user@x.com' } as Saml.Profile,
    })),
  }
  if (options) Object.assign(client, { options })
  return client
}

function build(options?: Record<string, unknown>) {
  return saml({
    allowUnsolicited: true,
    callbackUrl: 'https://app/acs',
    client: makeClient(options),
    onSignIn: async () => ({ identityId: 'x' }),
  })
}

describe('samlProvider refuses a client that verifies no signature at all', () => {
  // On `meta.detail`, not the code: this constructor answers AUTH_MISCONFIGURED for six other
  // reasons, so a code-only assertion would have been green before the guard existed.
  it('throws when the client disables both assertion and response signing', () => {
    expect(() => build({ wantAssertionsSigned: false, wantAuthnResponseSigned: false })).toThrowError(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: expect.objectContaining({ detail: expect.stringMatching(/verify no signature/i) }),
      }),
    )
  })

  it('accepts assertion-only signing, which is what most IdPs send', () => {
    expect(() => build({ wantAssertionsSigned: true, wantAuthnResponseSigned: false })).not.toThrow()
  })

  it('accepts response-only signing', () => {
    expect(() => build({ wantAssertionsSigned: false, wantAuthnResponseSigned: true })).not.toThrow()
  })

  it('leaves a client exposing no options alone', () => {
    expect(() => build()).not.toThrow()
    expect(() => build({ callbackUrl: 'https://app/acs' })).not.toThrow()
  })
})
