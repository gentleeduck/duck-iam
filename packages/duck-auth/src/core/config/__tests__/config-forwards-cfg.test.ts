import { afterEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId, setDefaultActorResolver } from '~/core/actor'
import { type AuthCaptcha, AuthUnconfiguredCaptchaVerifier } from '~/core/captcha'
import { createAuth } from '~/core/config/config'
import { idempotency as idempotencyFacet, MemoryIdempotency } from '~/core/idempotency'

function base() {
  const a = new MemoryAdapter()
  return {
    baseUrl: 'https://x.test',
    stores: { credentials: a.credentials, identities: a.identities, sessions: a.sessions },
  }
}

class MarkerVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'marker'
  async verify(_input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    return { success: true }
  }
}

/**
 * `AuthDefine.Cfg` inherits most of `Engine.Cfg`, so every one of these keys
 * type-checks at the `createAuth` call whether or not the factory forwards it.
 * A dropped key is therefore invisible to `tsc` and to the caller - it just
 * silently does nothing. These are the ones that were dropped.
 */
describe('createAuth forwards the whole engine config', () => {
  // Process-wide, so it does not stay set for whatever runs next.
  afterEach(() => setDefaultActorResolver(undefined))

  it('forwards captcha', () => {
    const verifier = new MarkerVerifier()
    expect(createAuth({ ...base(), captcha: verifier }).captcha).toBe(verifier)
  })

  it('leaves captcha refusing when none was given', () => {
    expect(createAuth(base()).captcha).toBeInstanceOf(AuthUnconfiguredCaptchaVerifier)
  })

  it('forwards resolveActor, so writes are attributed', () => {
    createAuth({ ...base(), resolveActor: () => 'ops-7' })
    // Not `null`: an unforwarded resolver leaves every `created_by` /
    // `updated_by` / `deleted_by` empty, which is the audit trail going missing
    // for exactly the host that took the trouble to wire one up.
    expect(actorId()).toBe('ops-7')
  })

  it('forwards idempotency', () => {
    const idempotency = idempotencyFacet(new MemoryIdempotency())
    expect(createAuth({ ...base(), idempotency }).idempotency).toBe(idempotency)
  })

  it('still defaults transport when none was given', () => {
    expect(createAuth(base()).transport).toBeDefined()
  })
})
