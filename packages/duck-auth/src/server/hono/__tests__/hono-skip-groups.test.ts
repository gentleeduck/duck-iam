/**
 * `opts.skip` is the only way a host removes routes it does not expose, and nothing exercised it. The
 * group names are also not a clean partition: `'totp'` takes backup-code regeneration with it, which the
 * name does not say.
 */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import type { MountHono } from '../hono.types'
import { mountHono } from '../index'

type MyProfile = { username: string; email: string }

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  return new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwords<MyProfile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

/** Mount against a recorder rather than a real Hono, which this package does not depend on. */
function pathsWith(opts: MountHono.Options): string[] {
  const seen: string[] = []
  const app: MountHono.App = {
    get(p) {
      seen.push(p)
    },
    post(p) {
      seen.push(p)
    },
  }
  mountHono(app, buildAuth(), opts)
  return seen.sort()
}

/** Mounted whatever is skipped: a host cannot opt out of sign-in. */
const ALWAYS = ['/auth/providers/:id/begin', '/auth/session', '/auth/signin', '/auth/signout']

describe('mountHono opts.skip', () => {
  const all = pathsWith({})

  it('mounts every group by default', () => {
    expect(all.length).toBeGreaterThan(ALWAYS.length)
    for (const p of ALWAYS) expect(all).toContain(p)
  })

  it.each([
    ['oauth', ['/auth/providers/:provider/callback']],
    ['magic-link', ['/auth/magic-link/verify']],
    ['passkey', ['/auth/passkey/begin', '/auth/passkey/complete']],
    [
      'totp',
      [
        '/auth/mfa/backup-codes/regenerate',
        '/auth/mfa/totp/begin',
        '/auth/mfa/totp/confirm',
        '/auth/mfa/totp/remove',
        '/auth/mfa/totp/verify',
      ],
    ],
  ] as const)('skipping %s removes exactly its own routes', (group, removed) => {
    const kept = pathsWith({ skip: [group] })
    expect(all.filter((p) => !kept.includes(p)).sort()).toEqual([...removed].sort())
    for (const p of ALWAYS) expect(kept).toContain(p)
  })

  it("'totp' takes backup-code regeneration with it, which its name does not say", () => {
    // Pinned because it is surprising, not because it is right: a host that offers backup codes but not
    // TOTP has no way to ask for that.
    expect(pathsWith({ skip: ['totp'] })).not.toContain('/auth/mfa/backup-codes/regenerate')
  })

  it('skipping every group leaves the core routes and nothing else', () => {
    expect(pathsWith({ skip: ['oauth', 'magic-link', 'passkey', 'totp'] })).toEqual(ALWAYS)
  })
})
