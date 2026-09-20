/**
 * `MfaImpl`'s class docstring says backup codes are single-use, and `verifyBackupCode` matched a live
 * row and then called `revoke` unconditionally. Two verifications that both read before either wrote
 * matched the same row and both answered `true`.
 */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'

type MyProfile = { username: string; email: string }

let seq = 0

async function enrolled(): Promise<{ auth: AuthEngine<MyProfile>; identityId: string; codes: string[] }> {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 99, windowMs: 60_000 }),
    providers: [mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const email = `a${seq++}@x.com`
  const ident = await auth.identities.create({ profile: { email, username: email } })
  const codes = await auth.mfa.regenerateBackupCodes(ident.id)
  return { auth, codes, identityId: ident.id }
}

describe('a backup code is spent once, as the docstring says', () => {
  it('two verifications of one code in the same tick do not both succeed', async () => {
    const { auth, codes, identityId } = await enrolled()
    const code = codes[0] as string

    const both = await Promise.all([
      auth.mfa.verifyBackupCode(identityId, code),
      auth.mfa.verifyBackupCode(identityId, code),
    ])

    expect(both.filter(Boolean)).toHaveLength(1)
  })

  it('the sequential replay stays refused', async () => {
    const { auth, codes, identityId } = await enrolled()
    const code = codes[0] as string

    expect(await auth.mfa.verifyBackupCode(identityId, code)).toBe(true)
    expect(await auth.mfa.verifyBackupCode(identityId, code)).toBe(false)
  })

  it('spending one code leaves the rest of the set usable', async () => {
    const { auth, codes, identityId } = await enrolled()

    await auth.mfa.verifyBackupCode(identityId, codes[0] as string)

    expect(await auth.mfa.verifyBackupCode(identityId, codes[1] as string)).toBe(true)
    expect(await auth.mfa.verifyBackupCode(identityId, codes[2] as string)).toBe(true)
  })
})
