/**
 * `MfaImpl._randomBackupCode` is the only randomness in this package that does not come from
 * `node:crypto`. It reaches for `globalThis.crypto.getRandomValues` behind a `typeof === 'function'`
 * guard and, when that guard is false, carries on with the zero-filled array it allocated.
 */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'

type MyProfile = { username: string; email: string }

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  return new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

let seq = 0
async function newIdentity(auth: AuthEngine<MyProfile>): Promise<string> {
  const email = `a${seq++}@x.com`
  const ident = await auth.identities.create({ profile: { email, username: email } })
  return ident.id
}

describe('backup codes do not depend on a global this package never needed', () => {
  it('mints distinct codes with no webcrypto on the global', async () => {
    const auth = buildAuth()
    const identityId = await newIdentity(auth)
    vi.stubGlobal('crypto', undefined)
    try {
      const codes = await auth.mfa.regenerateBackupCodes(identityId)
      expect(codes.length).toBeGreaterThan(1)
      expect(new Set(codes).size).toBe(codes.length)
      expect(codes).not.toContain('aaaaa-aaaaa')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('a code minted without webcrypto still verifies, so the set is usable', async () => {
    const auth = buildAuth()
    const identityId = await newIdentity(auth)
    vi.stubGlobal('crypto', undefined)
    let codes: string[]
    try {
      codes = await auth.mfa.regenerateBackupCodes(identityId)
    } finally {
      vi.unstubAllGlobals()
    }
    expect(await auth.mfa.verifyBackupCode(identityId, codes[0] as string)).toBe(true)
  })

  it('two calls do not repeat a code, webcrypto present or not', async () => {
    const auth = buildAuth()
    const a = await auth.mfa.regenerateBackupCodes(await newIdentity(auth))
    const b = await auth.mfa.regenerateBackupCodes(await newIdentity(auth))
    expect(new Set([...a, ...b]).size).toBe(a.length + b.length)
  })
})
