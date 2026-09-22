/**
 * Four places decide a session is past a deadline, delete the dead row so `gc` does not have to come round
 * to it, and throw the refusal — `AUTH_SESSION_EXPIRED` on a deadline, `AUTH_SESSION_REVOKED` on a closed
 * impersonation window. The delete was awaited bare, so a store that refused the write
 * threw `AUTH_ADAPTER_FAILED` in the refusal's place — and that code is not in `ABSENT`, so the
 * `resolveSession(...).orNull()` every server adapter calls rethrew it. A session that had merely expired
 * came back a 500 instead of a 401, on exactly the degraded store where expired rows pile up.
 *
 * The decision is made before the delete runs. What the cleanup does afterwards cannot be allowed to change
 * it, and the row is swept regardless.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { identityInput } from '~/test/store-inputs'
import { resolveBySid, SessionsImpl } from '../sessions'
import { DEFAULT_SESSION_CONFIG } from '../sessions.constants'

describe('an expiry cleanup that fails does not become the answer', () => {
  let adapter: MemoryAdapter
  let sessions: MemoryAdapter['sessions']
  let facet: SessionsImpl
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    // Only `delete` refuses; every read still works, which is the shape of a store under write pressure.
    sessions = {
      ...adapter.sessions,
      delete: async () => {
        throw new AuthError('AUTH_ADAPTER_FAILED', { detail: 'the store refused the write' })
      },
    }
    facet = new SessionsImpl(sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
    identityId = (
      await adapter.identities.create(identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }))
    ).id
  })

  /** A session live at creation, then pushed past its sliding deadline. `createdAt` moves with it. */
  async function expired(): Promise<string> {
    const { sid } = await facet.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId,
      kind: 'user',
    })
    await adapter.sessions.update(sha256(sid), {
      absoluteExpiresAt: new Date(Date.now() + 86_400_000),
      createdAt: new Date(Date.now() - 86_400_000),
      expiresAt: new Date(Date.now() - 1000),
    })
    return sid
  }

  it('getBySid still refuses the expired session, rather than reporting the failed write', async () => {
    await expect(facet.getBySid(await expired())).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
  })

  it('touch still refuses it, rather than reviving it or reporting the write', async () => {
    await expect(facet.touch(await expired())).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
  })

  it('resolveBySid still refuses it, which is the path every server adapter takes', async () => {
    await expect(resolveBySid(await expired(), sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_EXPIRED',
    })
  })

  it('resolveBySid still refuses a closed impersonation window', async () => {
    const { sid } = await facet.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId,
      kind: 'user',
    })
    await adapter.sessions.update(sha256(sid), {
      actingAs: {
        expiresAt: new Date(Date.now() - 1000),
        realIdentityId: 'admin',
        reason: 'support',
        startedAt: new Date(Date.now() - 2000),
      },
    })
    await expect(resolveBySid(sid, sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
  })

  it('reads as absent to a caller holding the readers, which is the 401 rather than the 500', async () => {
    // `AUTH_SESSION_EXPIRED` is in `ABSENT` and `AUTH_ADAPTER_FAILED` is not, so this is the whole
    // difference between the two at every route that resolves a session.
    await expect(facet.getBySid(await expired()).orNull()).resolves.toBeNull()
  })
})
