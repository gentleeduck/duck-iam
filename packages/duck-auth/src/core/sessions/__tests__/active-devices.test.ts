/** The "active devices" reads and counts: a session past its sliding or its absolute deadline is not one. */
import { expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { identityInput } from '~/test/store-inputs'
import { SessionsImpl } from '../sessions'
import { DEFAULT_SESSION_CONFIG } from '../sessions.constants'

/** One live session, one idle past its sliding deadline, one past its absolute deadline. */
async function devices() {
  const adapter = new MemoryAdapter()
  const facet = new SessionsImpl(adapter.sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
  const { id: identityId } = await adapter.identities.create(
    identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }),
  )
  const open = () => facet.create({ aal: 1, factors: [], identityId, kind: 'user' })
  const live = await open()
  const idle = await open()
  const capped = await open()
  const past = new Date(Date.now() - 1000)
  const opened = new Date(Date.now() - 86_400_000)
  await adapter.sessions.update(sha256(idle.sid), { createdAt: opened, expiresAt: past })
  await adapter.sessions.update(sha256(capped.sid), { absoluteExpiresAt: past, createdAt: opened, expiresAt: past })
  return { adapter, facet, identityId, live, open }
}

it('listForIdentity leaves out the expired sessions, and keeps the live one', async () => {
  const { adapter, facet, identityId, live } = await devices()
  expect((await facet.listForIdentity(identityId)).map((s) => s.id)).toEqual([live.session.id])
  // Left out, not deleted: sweeping stays `gc`'s job.
  expect(await adapter.sessions.listByIdentity(identityId)).toHaveLength(3)
})

it('revokeAllExcept counts only the live devices it signed out', async () => {
  const { facet, identityId, live, open } = await devices()
  const other = await open()
  expect(await facet.revokeAllExcept(identityId, live.sid)).toEqual({ revoked: 1 })
  expect(await facet.getBySid(other.sid).orNull()).toBeNull()
  expect(await facet.getBySid(live.sid).orNull()).not.toBeNull()
})

it('revokeAllForIdentity answers only the sessions that were live, and removes every row', async () => {
  const { adapter, facet, identityId, live } = await devices()
  expect((await facet.revokeAllForIdentity(identityId)).map((s) => s.id)).toEqual([live.session.id])
  expect(await adapter.sessions.listByIdentity(identityId)).toHaveLength(0)
})
