import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import {
  type AuthCaptcha,
  AuthNullCaptchaVerifier,
  AuthUnconfiguredCaptchaVerifier,
  authNullCaptchaVerifier,
} from '~/core/captcha'
import { createAuth } from '~/core/config/config'

function base() {
  const a = new MemoryAdapter()
  return {
    baseUrl: 'https://x.test',
    stores: { credentials: a.credentials, identities: a.identities, sessions: a.sessions },
  }
}

/** A stand-in for a real provider verifier, so `auth.captcha` has something to be. */
class RecordingVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'recording'
  readonly seen: AuthCaptcha.IVerifyInput[] = []
  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    this.seen.push(input)
    return { score: 0.9, success: true }
  }
}

describe('auth.captcha', () => {
  it('is the verifier that was configured', async () => {
    const verifier = new RecordingVerifier()
    const auth = createAuth({ ...base(), captcha: verifier })
    expect(auth.captcha).toBe(verifier)
    await auth.captcha.verify({ remoteIp: '203.0.113.9', token: 'tok' })
    expect(verifier.seen).toEqual([{ remoteIp: '203.0.113.9', token: 'tok' }])
  })

  it('exists without configuration, so a host never dereferences undefined', () => {
    const auth = createAuth(base())
    expect(auth.captcha).toBeInstanceOf(AuthUnconfiguredCaptchaVerifier)
    expect(auth.captcha.id).toBe('unconfigured')
  })

  it('refuses rather than passes when nothing was configured', async () => {
    const auth = createAuth(base())
    // The whole point of the default. A host that guards a route with
    // `if (!(await auth.captcha.verify(...)).success) throw` and ships with the
    // secret unset gets a closed door, not an open one that reads as closed.
    await expect(auth.captcha.verify({ token: 'whatever' })).resolves.toEqual({
      errorCodes: ['captcha-not-configured'],
      success: false,
    })
  })

  it('refuses every token, including the empty one', async () => {
    const auth = createAuth(base())
    for (const token of ['', 'x', 'a'.repeat(4096)]) {
      const result = await auth.captcha.verify({ token })
      expect(result.success).toBe(false)
    }
  })

  it('lets a caller opt into always-pass explicitly', async () => {
    const auth = createAuth({ ...base(), captcha: authNullCaptchaVerifier() })
    expect(auth.captcha).toBeInstanceOf(AuthNullCaptchaVerifier)
    await expect(auth.captcha.verify({ token: 'anything' })).resolves.toEqual({ success: true })
  })
})
