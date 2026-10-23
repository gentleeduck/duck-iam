import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { authTestDeliver } from '~/test'

function engine(baseUrl: string) {
  const adapter = new MemoryAdapter()
  const channel = authTestDeliver()
  const auth = new AuthEngine({
    baseUrl,
    deliver: channel.deliver,
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
  })
  return { auth, channel }
}

async function mailedPath(baseUrl: string): Promise<string> {
  const { auth, channel } = engine(baseUrl)
  const ident = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
  await auth.flows.requestEmailVerification({ identityId: ident.id })
  const vars = channel.outbox[0]?.vars
  if (!vars || typeof vars !== 'object' || !('url' in vars) || typeof vars.url !== 'string') {
    throw new Error('expected outbox[0].vars.url to be a string')
  }
  return new URL(vars.url).pathname
}

describe('new AuthEngine reads baseUrl as createAuth does', () => {
  it('mails /path, not //path, from a baseUrl written with a trailing slash', async () => {
    expect(await mailedPath('https://app.example.com/')).toBe('/auth/verify-email')
    expect(await mailedPath('https://app.example.com/base/')).toBe('/base/auth/verify-email')
    expect(await mailedPath('https://app.example.com/base')).toBe('/base/auth/verify-email')
  })

  it('refuses a baseUrl that is not an absolute http(s) URL when built, not at the first email', () => {
    for (const baseUrl of ['', 'app.example.com', 'javascript:alert(1)']) {
      expect(() => engine(baseUrl)).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
  })
})
