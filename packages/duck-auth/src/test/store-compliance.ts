/** The compliance matrices every shipped adapter runs against a fresh instance of itself, so the assertions that
 *  guarantee parity between them live in one place. */

import { describe, expect, it } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import { withActor } from '~/core/actor'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7, sha256 } from '~/core/crypto'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import {
  CREDENTIAL_FIELDS,
  CREDENTIAL_KEYS,
  expectRow,
  IDENTITY_FIELDS,
  IDENTITY_KEYS,
  SESSION_FIELDS,
  SESSION_KEYS,
} from '~/test/type-fidelity'

/** An identity id guaranteed both absent and acceptable to the adapter's `id` column. A literal like
 *  `'no-such-id'` is neither, Postgres typing the column `uuid` and rejecting it as malformed long before it
 *  can miss, so creating a row and erasing it borrows the store's own id shape. */
async function absentIdentityId<P extends Identities.ProfileMetadataBase>(
  store: Identities.Store<P>,
): Promise<string> {
  const doomed = await store.create(
    identityInput({ profile: profileOf<P>(`absent-${Date.now()}@x`, 'absent') }),
  )
  await store.erase(doomed.id)
  return doomed.id
}

/** A profile literal for the suite's unbound `P`, and the one assertion in this file. Every adapter instantiates
 *  the suite with `{ username, email }` and nothing here touches another key, but inside a function generic over
 *  `P extends ProfileMetadataBase` the parameter could be narrower than any literal, so `identityInput<P>`
 *  refuses one. A caller binding `P` to a concrete type needs no assertion at all. */
function profileOf<P>(email: string, username: string): P {
  return { email, username } as P
}

/** Same idea for session compliance, whose identity ids come from the caller. */
const ABSENT = '00000000-0000-4000-8000-000000000000'

/** `withClient` is the adapter's, not a facet's: one rebind puts every store on the caller's transaction, since
 *  they share the one connection. An adapter with no transactional driver omits it by design. WARN: an absent
 *  optional method is `ctx.skip()`, never a bare `return`, which reports a PASS for a test that ran nothing,
 *  so an adapter that quietly stopped implementing this reads exactly like one that still does. */
export function runAdapterRebindCompliance<P extends Identities.ProfileMetadataBase>(
  factory: () => Adapter.Me<P>,
  /** A handle the adapter's `withClient` accepts. The suite cannot invent one, and a bridge that validates
   *  its handle is right to refuse a stand-in. */
  client: () => unknown,
): void {
  describe('Adapter.withClient compliance', () => {
    it('returns a distinct adapter, facets included', (ctx) => {
      const adapter = factory()
      if (!adapter.withClient) return ctx.skip()

      // Never `this`: a bound facade sharing identity with the engine's own adapter could mutate it, which
      // is the whole failure mode withClient prevents.
      const bound = adapter.withClient(client())
      expect(bound).not.toBe(adapter)
      expect(bound.identities).not.toBe(adapter.identities)
      expect(bound.credentials).not.toBe(adapter.credentials)
      expect(bound.sessions).not.toBe(adapter.sessions)
    })
  })
}

export function runIdentityStoreCompliance<P extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  factory: () => Identities.Store<P>,
): void {
  describe('Identity.IStore compliance', () => {
    /** The row type says `Date`, `number`, `boolean`, and a driver handing back the serialised form satisfies
     *  `tsc` all the same, because nothing re-checks a value once it crosses the driver boundary. Every read path
     *  is checked, not just `create`, which builds the row in memory and may never touch the database. */
    it('every read path returns the field types the row type declares', async () => {
      const store = factory()
      const created = await store.create(
        identityInput({
          profile: profileOf<P>('fidelity@x.com', 'fidelity'),
          providers: [{ addedAt: new Date(), providerId: 'password', providerSub: 'sub-1' }],
        }),
      )
      expectRow(created, IDENTITY_FIELDS, IDENTITY_KEYS, 'create')
      expectRow(await store.find({ id: created.id }), IDENTITY_FIELDS, IDENTITY_KEYS, 'findById')
      expectRow(
        await store.find({ providerId: 'password', providerSub: 'sub-1' }),
        IDENTITY_FIELDS, IDENTITY_KEYS,
        'findByProviderSub',
      )
      expectRow(
        await store.update(created.id, { emailVerified: true }, created.version),
        IDENTITY_FIELDS, IDENTITY_KEYS,
        'update',
      )
      const linked = await store.link(created.id, {
        addedAt: new Date(),
        providerId: 'authGoogle',
        providerSub: 'g-1',
      })
      expectRow(linked, IDENTITY_FIELDS, IDENTITY_KEYS, 'link')
      expectRow(await store.unlink(created.id, 'authGoogle'), IDENTITY_FIELDS, IDENTITY_KEYS, 'unlink')
      // A soft-deleted row is the one case with every nullable date populated.
      const deleted = await store.softDelete(created.id, 60_000)
      expectRow(deleted, IDENTITY_FIELDS, IDENTITY_KEYS, 'softDelete')
      expect(deleted?.deletedAt).toBeInstanceOf(Date)
      expectRow(await store.restore(created.id), IDENTITY_FIELDS, IDENTITY_KEYS, 'restore')
    })

    it('create stamps id, version=1, createdAt, updatedAt; respects providers + tenantId', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({
          profile: profileOf<P>('a@x.com', 'a'),
          providers: [{ providerId: 'oauth:authGoogle', providerSub: 'create-sub', addedAt: new Date() }],
        }),
      )
      expect(i.id).toBeTruthy()
      expect(i.version).toBe(1)
      expect(i.providers).toHaveLength(1)
      expect(i.createdAt).toBeInstanceOf(Date)
    })

    /** One rule for all three lifecycle writes: an id that matched nothing raises `AUTH_IDENTITY_NOT_FOUND`,
     *  while a row that WAS matched and then refused raises the rule that refused it. */
    it('softDelete, restore and erase all raise for an id that matched nothing', async () => {
      const store = factory()
      const gone = await absentIdentityId(store)

      await expect(store.softDelete(gone, 60_000)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(store.restore(gone)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(store.erase(gone)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    /** Pins that an ambient actor reaches the provenance columns at all, and that `createdBy` is written once
     *  and never re-stamped by a later writer. */
    it('a write under an ambient actor stamps provenance, and an update moves only updatedBy', async () => {
      const store = factory()
      const created = await withActor('op-1', () =>
        store.create(identityInput({ profile: profileOf<P>('prov@x', 'prov') })),
      )
      expect(created.createdBy).toBe('op-1')
      expect(created.updatedBy).toBe('op-1')

      const updated = await withActor('op-2', () =>
        store.update(created.id, { profile: profileOf<P>('prov2@x', 'prov') }, created.version),
      )
      // Who made the row is not who last touched it.
      expect(updated?.createdBy).toBe('op-1')
      expect(updated?.updatedBy).toBe('op-2')
    })

    it('a provider link records who attached it, on create and on link alike', async () => {
      const store = factory()
      const created = await withActor('op-link', () =>
        store.create(
          identityInput({
            profile: profileOf<P>('addedby@x', 'addedby'),
            providers: [{ providerId: 'oauth:authGoogle', providerSub: 'ab-1' }],
          }),
        ),
      )
      expect(created.providers[0]?.addedBy).toBe('op-link')

      // An admin attaching a login and the account holder attaching their own must not read alike, so
      // the second link carries its own actor rather than the one that made the row.
      const linked = await withActor('op-other', () =>
        store.link(created.id, { providerId: 'saml:acme', providerSub: 'ab-2' }),
      )
      const attached = linked?.providers.find((p) => p.providerId === 'saml:acme')
      expect(attached?.addedBy).toBe('op-other')
      expect(linked?.providers.find((p) => p.providerId === 'oauth:authGoogle')?.addedBy).toBe('op-link')
    })

    it('a provider link attached with no actor bound records null, not a placeholder', async () => {
      const store = factory()
      const created = await store.create(
        identityInput({
          profile: profileOf<P>('noactor-link@x', 'noactorlink'),
          providers: [{ providerId: 'oauth:authGoogle', providerSub: 'na-1' }],
        }),
      )
      expect(created.providers[0]?.addedBy).toBeNull()
    })

    it('a write with no actor bound records null, not a placeholder', async () => {
      const store = factory()
      const created = await store.create(identityInput({ profile: profileOf<P>('anon@x', 'anon') }))

      // NULL here means "nothing was in scope", which is a true statement. A
      // stand-in like 'system' would assert an actor that never existed.
      expect(created.createdBy).toBeNull()
      expect(created.updatedBy).toBeNull()
    })

    it('a soft delete records who did it, and a restore clears the claim', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('del@x', 'del') }))
      expect(i.deletedBy).toBeNull()

      const hidden = await withActor('op-5', () => store.softDelete(i.id, 60_000))
      // "Who deleted this account" is the audit question that actually gets
      // asked, and `deleted_at` alone cannot answer it.
      expect(hidden?.deletedBy).toBe('op-5')

      const back = await store.restore(i.id)
      // A live row names no deleter: leaving `deletedBy` set would accuse an
      // operator of a deletion that is no longer in effect.
      expect(back?.deletedAt).toBeNull()
      expect(back?.deletedBy).toBeNull()
    })

    it('every write that touches the row moves updatedAt, links included', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('touch@x', 'touch') }))
      await new Promise((r) => setTimeout(r, 25))

      // `$onUpdate` moves it on every dialect, so a store that only stamps it on `update` reports an
      // identity as untouched since signup after its logins have been rewired.
      const linked = await store.link(i.id, { addedAt: new Date(), providerId: 'google', providerSub: 'sub-touch' })
      expect(linked.updatedAt.getTime()).toBeGreaterThan(i.updatedAt.getTime())

      await new Promise((r) => setTimeout(r, 25))
      const unlinked = await store.unlink(i.id, 'google')
      expect(unlinked.updatedAt.getTime()).toBeGreaterThan(linked.updatedAt.getTime())
    })

    it('restoring a row that was never hidden answers it, rather than raising', async () => {
      const store = factory()
      const live = await store.create(identityInput({ profile: profileOf<P>('live@x', 'live') }))

      // Nothing to undo is not a closed window: `AUTH_GRACE_EXPIRED` here would tell a caller retrying a
      // restore that the account is past saving, when it is simply already live.
      const back = await store.restore(live.id)
      expect(back?.id).toBe(live.id)
      expect(back?.deletedAt).toBeNull()
      expect(back?.version).toBe(live.version)
    })

    it('a hidden row keeps its provider login, so restore has nothing to refuse', async () => {
      const store = factory()
      const a = await store.create(identityInput({ profile: profileOf<P>('pa@x', 'pa') }))
      await store.link(a.id, { addedAt: new Date(), providerId: 'google', providerSub: 'sub-shared' })
      await store.softDelete(a.id, 60_000)

      // Unreadable, but not unclaimed: `findByProviderSub` hides the row while
      // `uq_auth_identity_providers_sub`, which is not partial, still holds the login.
      await expect(store.find({ providerId: 'google', providerSub: 'sub-shared' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      const b = await store.create(identityInput({ profile: profileOf<P>('pb@x', 'pb') }))
      await expect(
        store.link(b.id, { addedAt: new Date(), providerId: 'google', providerSub: 'sub-shared' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })

      // Letting B take it would end A's only way back, which is what the grace window promises not to do.
      expect((await store.restore(a.id)).id).toBe(a.id)
      expect((await store.find({ providerId: 'google', providerSub: 'sub-shared' }))?.id).toBe(a.id)
    })

    it('findByEmail finds a created identity (identities are global)', async () => {
      const store = factory()
      await store.create(identityInput({ profile: profileOf<P>('shared@x', 'shared') }))
      await expect(store.find({ email: 'shared@x' })).resolves.toBeTruthy()
    })

    it('update with expectedVersion mismatch surfaces AUTH_STALE_WRITE', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('a@x', 'a') }))
      await store.update(i.id, { profile: profileOf<P>('b@x', 'b') }, i.version)
      await expect(store.update(i.id, { profile: profileOf<P>('c@x', 'c') }, 1)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
    })

    it('admits exactly one of many concurrent updates from the same version', async () => {
      // Two request handlers reading the same row and both writing is the ordinary
      // case for a profile edit. Whichever concurrency control the adapter has, the
      // observable contract is the same: one write lands, the rest are refused, and
      // the version advances exactly once.
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('race@x', 'race') }))

      const settled = await Promise.allSettled(
        Array.from({ length: 10 }, (_, n) =>
          store.update(i.id, { profile: profileOf<P>('race@x', `race-${n}`) }, i.version),
        ),
      )

      expect(settled.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
      for (const r of settled) {
        if (r.status === 'rejected') expect(r.reason).toMatchObject({ code: 'AUTH_STALE_WRITE' })
      }
      expect((await store.find({ id: i.id }))?.version).toBe(i.version + 1)
    })

    it('softDelete hides; restore brings back within grace; erase is permanent', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('a@x', 'a') }))
      await store.softDelete(i.id, 60_000)
      await expect(store.find({ id: i.id })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      const restored = await store.restore(i.id)
      expect(restored?.id).toBe(i.id)
      await store.erase(i.id)
      await expect(store.find({ id: i.id })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('softDelete clears emailVerified, so a restore does not hand back a verified claim', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({ emailVerified: true, profile: profileOf<P>('a@x', 'a') }),
      )
      expect(i.emailVerified).toBe(true)

      await store.softDelete(i.id, 60_000)

      // Verification is a claim about a moment, and the grace window can be long. Restoring must not
      // hand back an assertion nobody re-proved in between.
      const restored = await store.restore(i.id)
      expect(restored?.emailVerified).toBe(false)
      expect((await store.find({ id: i.id }))?.emailVerified).toBe(false)
    })

    it('restore refuses once the grace window has closed', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('a@x', 'a') }))

      // `deletedAt` holds the moment the window shuts, so a negative grace is a
      // window that shut before it opened, the same state a row reaches by
      // simply sitting there, without the test having to wait for it.
      await store.softDelete(i.id, -1000)

      await expect(store.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
      // Still gone: a refused restore must not half-apply.
      await expect(store.find({ id: i.id })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('a hidden row keeps its address, so restore has nothing to refuse', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('a@x', 'a') }))
      await store.softDelete(i.id, 60_000)

      // `findByEmail` skips the hidden row, but `uq_auth_identities_email` is not partial, so the address
      // is still spoken for. A different username, so this pins the email index rather than the other.
      await expect(
        store.create(identityInput({ profile: profileOf<P>('a@x', 'a2') })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })

      expect((await store.restore(i.id)).id).toBe(i.id)
      expect((await store.find({ email: 'a@x' }))?.id).toBe(i.id)
    })

    /** Every dialect declares unique indexes on email and username, neither partial on `deletedAt`. A store that
     *  admits a duplicate holds state Postgres will not, so every test running on it asserts behaviour the real
     *  adapters do not have, which is why the rule belongs to the contract. */
    it('create refuses a second live row with the same email', async () => {
      const store = factory()
      await store.create(identityInput({ profile: profileOf<P>('dup@x', 'one') }))
      // A different handle, so this pins the email index rather than the other.
      await expect(
        store.create(identityInput({ profile: profileOf<P>('DUP@x', 'two') })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })

    it('create refuses a second live row whose address differs only by composition', async () => {
      const store = factory()
      // 'cafe' + combining acute against the precomposed form. One address to a reader, and no
      // dialect's `lower()` folds the difference, so the store is what has to.
      await store.create(identityInput({ profile: profileOf<P>('cafe\u0301@x', 'one-nfd') }))
      await expect(
        store.create(identityInput({ profile: profileOf<P>('caf\u00e9@x', 'two-nfc') })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })

    it('find matches a row under any spelling of its address, not only the stored one', async () => {
      const store = factory()
      // Stored composed, looked up decomposed: one address to a reader, two byte strings to `lower()`.
      const created = await store.create(identityInput({ profile: profileOf<P>('caf\u00e9@x', 'spellings') }))
      expect((await store.find({ email: 'cafe\u0301@x' }))?.id).toBe(created.id)
    })

    it('find matches nothing for a blank address rather than the first live row', async () => {
      const store = factory()
      await store.create(identityInput({ profile: profileOf<P>('any@x', 'any') }))
      await expect(store.find({ email: '   ' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('create refuses a second live row with the same username', async () => {
      const store = factory()
      await store.create(identityInput({ profile: profileOf<P>('one@x', 'dup') }))
      // Distinct address, same handle: reporting this as the email clash would
      // send the caller off to change a field that is not the problem.
      await expect(
        store.create(identityInput({ profile: profileOf<P>('two@x', 'DUP') })),
      ).rejects.toMatchObject({ code: 'AUTH_USERNAME_TAKEN' })
    })

    it('a soft-deleted row keeps its email and username until it is erased', async () => {
      const store = factory()
      const first = await store.create(identityInput({ profile: profileOf<P>('g@x', 'g') }))
      await store.softDelete(first.id, 60_000)

      // Handing the address out during the grace window is what would make the window a lie: the row
      // could no longer come back, and nothing would say why. A different handle each time, so this
      // pins the email index rather than the username one.
      await expect(
        store.create(identityInput({ profile: profileOf<P>('g@x', 'g2') })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })

      // Erase is the release, and the control for the refusal above: without it this would also pass
      // against a store that refused duplicates unconditionally.
      await store.erase(first.id)
      await expect(
        store.create(identityInput({ profile: profileOf<P>('g@x', 'g3') })),
      ).resolves.toBeDefined()
    })

    it('update refuses moving onto another live row profile', async () => {
      const store = factory()
      const holder = await store.create(identityInput({ profile: profileOf<P>('h@x', 'h') }))
      const mover = await store.create(identityInput({ profile: profileOf<P>('m@x', 'm') }))

      await expect(
        store.update(mover.id, { profile: profileOf<P>('h@x', 'm') }, mover.version),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
      // Refused, not half-applied: the row keeps the address it had.
      expect((await store.find({ id: mover.id }))?.profile).toMatchObject({ email: 'm@x' })
      expect((await store.find({ id: holder.id }))?.id).toBe(holder.id)
    })

    it('update leaves a row its own profile without tripping the indexes', async () => {
      const store = factory()
      const row = await store.create(identityInput({ profile: profileOf<P>('s@x', 's') }))
      // The refusal above must exclude the row being updated, or no identity
      // could ever be patched without also changing its email.
      const next = await store.update(row.id, { emailVerified: true }, row.version)
      expect(next.emailVerified).toBe(true)
    })

    it('link / unlink mutate providers; findByProviderSub locates linked identities', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('a@x', 'a') }))
      await store.link(i.id, { providerId: 'oauth:authGoogle', providerSub: 'sub-1', addedAt: new Date() })
      const found = await store.find({ providerId: 'oauth:authGoogle', providerSub: 'sub-1' })
      expect(found?.id).toBe(i.id)
      await store.unlink(i.id, 'oauth:authGoogle')
      await expect(store.find({ providerId: 'oauth:authGoogle', providerSub: 'sub-1' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('a provider link comes back as a real Date, not the string a JSON column stores', async () => {
      const store = factory()
      const addedAt = new Date()
      const i = await store.create(identityInput({ profile: profileOf<P>('d@x', 'd') }))
      const linked = await store.link(i.id, { addedAt, providerId: 'oauth:authGoogle', providerSub: 'sub-1' })

      // `providers` is a JSON column on every SQL dialect, and `JSON.stringify`
      // turns a Date into an ISO string. The row type says `Date`, and the
      // memory store hands back one, so a caller reading `addedAt.getTime()`
      // must not have to know which adapter it is talking to.
      expect(linked?.providers[0]?.addedAt).toBeInstanceOf(Date)
      expect(linked?.providers[0]?.addedAt.getTime()).toBe(addedAt.getTime())

      const reread = await store.find({ id: i.id })
      expect(reread?.providers[0]?.addedAt).toBeInstanceOf(Date)
      expect(reread?.providers[0]?.addedAt.getTime()).toBe(addedAt.getTime())
    })

    it('re-linking the identical provider sub is a no-op, not a second entry', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('rl@x', 'rl') }))
      const link = { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'sub-rl' }
      await store.link(i.id, link)
      // A retried OAuth callback is the ordinary way this happens. Appending
      // would grow the JSON array without bound, and `unlink(providerId)` then
      // removes every copy at once.
      await store.link(i.id, link)
      const reread = await store.find({ id: i.id })
      expect(reread?.providers.filter((l) => l.providerSub === 'sub-rl')).toHaveLength(1)
    })

    /** `providers` lives in a json column, which stores a `Date` as a string and hands one back, while
     *  `ProviderLink.addedAt` is typed `Date`, so every read path has to revive it or the type is a lie. Pinned
     *  on every read that can carry a link and on the write that creates one, because a reviver applied to three
     *  of four paths works until the one call site nobody tested. */
    it('a provider link comes back as a real Date from every read', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('pl-d@x', 'pld') }))
      const addedAt = new Date('2024-03-01T12:00:00.000Z')

      const written = await store.link(i.id, { addedAt, providerId: 'oauth:authGoogle', providerSub: 'date-sub' })
      const paths: [string, Identities.Me<P> | null][] = [
        ['link', written],
        ['findById', await store.find({ id: i.id })],
        ['findByEmail', await store.find({ email: 'pl-d@x' })],
        ['findByProviderSub', await store.find({ providerId: 'oauth:authGoogle', providerSub: 'date-sub' })],
      ]

      for (const [path, row] of paths) {
        const link = row?.providers.find((l) => l.providerSub === 'date-sub')
        expect(link, path).toBeDefined()
        expect(link?.addedAt, path).toBeInstanceOf(Date)
        expect(link?.addedAt.getTime(), path).toBe(addedAt.getTime())
      }
    })

    it('refuses to link a provider sub that already belongs to a different identity', async () => {
      const store = factory()
      const first = await store.create(identityInput({ profile: profileOf<P>('o1@x', 'o1') }))
      const second = await store.create(identityInput({ profile: profileOf<P>('o2@x', 'o2') }))
      await store.link(first.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'shared-sub' })

      // Without this an attacker who can drive a link for a sub they control
      // attaches it to someone else's account, and every later sign-in through
      // that provider resolves to the victim.
      await expect(
        store.link(second.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'shared-sub' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })
      expect((await store.find({ providerId: 'oauth:authGoogle', providerSub: 'shared-sub' }))?.id).toBe(first.id)
    })

    /** `version` is what `update` locks against, so every write the row accepts has to move it. A write that
     *  leaves it alone lets a caller holding the old number pass the check on a row that changed underneath. */
    it('every accepted write moves the version, so a stale conditional update cannot pass', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('ver@x', 'ver') }))
      let seen = i.version

      const moved = async (label: string, write: Promise<{ version: number }>) => {
        const after = await write
        expect.soft(after.version, label).toBeGreaterThan(seen)
        seen = after.version
      }

      await moved('link', store.link(i.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'v1' }))
      await moved('unlink', store.unlink(i.id, 'oauth:authGoogle'))
      await moved('softDelete', store.softDelete(i.id, 60_000))
      await moved('restore', store.restore(i.id))

      // The lock itself: the number the caller read before those writes no longer reaches the row.
      await expect(store.update(i.id, { emailVerified: true }, i.version)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      expect((await store.update(i.id, { emailVerified: true }, seen)).version).toBeGreaterThan(seen)
    })

    /** The guard above counts hidden holders too, matching the address rule: freeing the sub the moment a row is
     *  hidden lets the next caller take the account and leaves its owner no way back, which is the one thing the
     *  grace window promises. Erase is what releases it. */
    it('a soft-deleted holder keeps its provider sub until it is erased', async () => {
      const store = factory()
      const first = await store.create(identityInput({ profile: profileOf<P>('fh1@x', 'fh1') }))
      const second = await store.create(identityInput({ profile: profileOf<P>('fh2@x', 'fh2') }))
      await store.link(first.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'freed-sub' })
      await store.softDelete(first.id, 60_000)

      // Unreadable and still claimed: the read side hides the row, the write side keeps refusing it.
      await expect(store.find({ providerId: 'oauth:authGoogle', providerSub: 'freed-sub' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(
        store.link(second.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'freed-sub' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })

      await store.erase(first.id)
      await store.link(second.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'freed-sub' })
      expect((await store.find({ providerId: 'oauth:authGoogle', providerSub: 'freed-sub' }))?.id).toBe(second.id)
    })

    it('softDelete on an already-hidden row raises and leaves the deadline where it was', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('sd@x', 'sd') }))
      const first = await store.softDelete(i.id, 60_000)
      expect(first).not.toBeNull()

      // Re-stamping would push the purge deadline forward every time it was
      // called, so a row queued for hard deletion could be kept alive
      // indefinitely by repeating a delete that changes nothing.
      await expect(store.softDelete(i.id, 60_000)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('softDeleteMany answers the rows it hid, and only those', async () => {
      const store = factory()
      const live = await store.create(identityInput({ profile: profileOf<P>('sdm@x', 'sdm') }))
      const shut = await store.create(identityInput({ profile: profileOf<P>('sdm2@x', 'sdm2') }))
      const absent = await absentIdentityId(store)
      await store.softDelete(shut.id, -1000)

      // Neither the absent id nor the already-hidden one comes back, which is how the facet tells a miss.
      const hid = await store.softDeleteMany([live.id, absent, shut.id], 60_000)

      expect(hid.map((row) => row.id)).toEqual([live.id])
      // The row as the write left it, not as it was read: the caller gets the new window without asking again.
      expect(hid[0]?.deletedAt?.getTime()).toBeGreaterThan(Date.now())
      expect(hid[0]?.version).toBe(live.version + 1)
      await expect(store.find({ id: live.id })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })

      // The same rule the single-row form keeps: a row already hidden is left out and its purge
      // deadline stays shut, or a sweep run twice keeps the queue alive forever.
      await expect(store.restore(shut.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
    })

    it('eraseMany answers the rows it erased, and only those', async () => {
      const store = factory()
      const live = await store.create(identityInput({ profile: profileOf<P>('em@x', 'em') }))
      const hidden = await store.create(identityInput({ profile: profileOf<P>('em2@x', 'em2') }))
      const absent = await absentIdentityId(store)
      // A hard erase reaches a hidden row, where a soft delete does not; purge runs on exactly those.
      await store.softDelete(hidden.id, 60_000)

      const gone = await store.eraseMany([live.id, absent, hidden.id])

      expect(gone.map((row) => row.id).sort()).toEqual([live.id, hidden.id].sort())
      // The row as it stood just before it went, logins and all, which is the last chance to read it.
      expect(gone.find((row) => row.id === live.id)).toEqual(live)
      await expect(store.find({ id: live.id })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      // Gone, not hidden: the address is free again, which a soft delete would still be holding.
      const reused = await store.create(identityInput({ profile: profileOf<P>('em@x', 'em') }))
      expect(reused.id).not.toBe(live.id)
    })

    it('a bulk call with no ids touches nothing', async () => {
      const store = factory()
      const kept = await store.create(identityInput({ profile: profileOf<P>('bulk0@x', 'bulk0') }))

      // Both reach the table through `inArray(col, [])`, which drizzle renders as `false`. Were it ever to
      // render as a missing condition, these two would hide and then erase every identity there is.
      expect(await store.softDeleteMany([], 60_000)).toEqual([])
      expect(await store.eraseMany([])).toEqual([])
      await expect(store.find({ id: kept.id })).resolves.toBeTruthy()
    })

    /** The other half of a soft delete: without this a row whose window closed stays hidden forever, which is
     *  a row nobody can reach and nobody deleted. A row still inside its window is not `gc`'s business. */
    it('gc erases the rows whose grace window has closed, and only those', async () => {
      const store = factory()
      const live = await store.create(identityInput({ profile: profileOf<P>('gcl@x', 'gcl') }))
      const waiting = await store.create(identityInput({ profile: profileOf<P>('gcw@x', 'gcw') }))
      const over = await store.create(identityInput({ profile: profileOf<P>('gco@x', 'gco') }))
      await store.softDelete(waiting.id, 60_000)
      await store.softDelete(over.id, -1000)

      expect((await store.gc(Date.now())).deleted).toBe(1)

      // Gone for real, not hidden: the address is free again, which a soft-deleted row would still hold.
      const reused = await store.create(identityInput({ profile: profileOf<P>('gco@x', 'gco') }))
      expect(reused.id).not.toBe(over.id)
      // The one still inside its window is untouched, and still restorable.
      expect((await store.restore(waiting.id)).id).toBe(waiting.id)
      await expect(store.find({ id: live.id })).resolves.toBeTruthy()
    })

    /** Same cutoff, same disagreement: `deletedAt < Infinity` is true for every soft-deleted row, so the
     *  erase took rows still inside their restore window, while `deletedAt < NaN` is false for all of them
     *  and the purge that makes a soft delete a delete silently never ran. */
    it('gc refuses a cutoff that is not a finite timestamp, and erases nothing when it does', async () => {
      const store = factory()
      const waiting = await store.create(identityInput({ profile: profileOf<P>('gcbad@x', 'gcbad') }))
      await store.softDelete(waiting.id, 60_000)
      for (const cutoff of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
        await expect(store.gc(cutoff)).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      }
      // Still inside its window and still restorable: a refused sweep must not be a partial one.
      expect((await store.restore(waiting.id)).id).toBe(waiting.id)
    })


    it('update leaves a field alone when the patch carries an explicit undefined', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({ emailVerified: true, profile: profileOf<P>('eu@x', 'eu') }),
      )
      // `{ profile: maybeProfile }` with nothing to say means "leave it alone",
      // never "clear the column", which is what a bare spread would do.
      const next = await store.update(i.id, { profile: undefined }, i.version)
      expect(next.profile).toEqual(i.profile)
    })

    /** `find` hides the row; these are the write paths, still reachable by a caller holding an id and a version
     *  from before the delete. `unlink` detached the login and then reported failure, and `update` handed back
     *  the `emailVerified` that `softDelete` clears precisely so a restore cannot. */
    it('a hidden identity takes no write', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({
          emailVerified: true,
          profile: profileOf<P>('hw@x', 'hw'),
          providers: [{ addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'hw-sub' }],
        }),
      )
      const hidden = await store.softDelete(i.id, 60_000)

      await expect(
        store.link(i.id, { addedAt: new Date(), providerId: 'oauth:authGithub', providerSub: 'hw-2' }),
      ).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(store.unlink(i.id, 'oauth:authGoogle')).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })
      // The version handed in is the one the delete left, so the gate is the only reason this can fail.
      await expect(store.update(i.id, { emailVerified: true }, hidden.version)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })

      // Nothing partial landed: the restored row is the one the delete left behind.
      const back = await store.restore(i.id)
      expect(back?.emailVerified).toBe(false)
      expect(back?.providers.map((link) => link.providerId)).toEqual(['oauth:authGoogle'])
    })

    it('every mutating write answers with the row it touched', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('ret@x', 'ret') }))

      const linked = await store.link(i.id, {
        addedAt: new Date(),
        providerId: 'oauth:authGoogle',
        providerSub: 'ret-1',
      })
      expect(linked?.id).toBe(i.id)
      expect(linked?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)

      const unlinked = await store.unlink(i.id, 'oauth:authGoogle')
      expect(unlinked?.id).toBe(i.id)
      expect(unlinked?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(false)

      // `deletedAt` is the moment the grace window CLOSES, so the deadline a
      // caller reports comes off the row the store wrote rather than a second
      // reading of the clock.
      const before = Date.now()
      const hidden = await store.softDelete(i.id, 60_000)
      expect(hidden?.id).toBe(i.id)
      expect(hidden?.deletedAt?.getTime()).toBeGreaterThanOrEqual(before + 60_000)
      expect(hidden?.emailVerified).toBe(false)

      const back = await store.restore(i.id)
      expect(back?.deletedAt).toBeNull()

      // The row as it was, links and all: once the delete lands there is nothing left to read, so what
      // the cascade takes has to leave on the answer.
      await store.link(i.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'ret-2' })
      const erased = await store.erase(i.id)
      expect(erased?.id).toBe(i.id)
      expect(erased?.providers.map((p) => p.providerSub)).toEqual(['ret-2'])
      await expect(store.find({ id: i.id })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('a write that matches no row raises rather than reporting a change', async () => {
      const store = factory()
      // A real id whose row is gone, valid for every dialect's id column,
      // which a made-up string would not be.
      const gone = (await store.create(identityInput({ profile: profileOf<P>('g@x', 'g') }))).id
      await store.erase(gone)

      await expect(store.softDelete(gone, 60_000)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(store.erase(gone)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(
        store.link(gone, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'gone-sub' }),
      ).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(store.unlink(gone, 'oauth:authGoogle')).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })
  })
}

/** Row identifiers the session and credential matrices plant. The short readable defaults are all a permissive
 *  store needs; an adapter with a strict schema overrides them, since Postgres types `identity_id` as a `uuid`
 *  behind a foreign key and pins `auth_sessions.id` to exactly 64 chars. */
export type ComplianceIds = {
  /** Owning identity. Must already exist when the adapter enforces the FK. */
  identityId?: string
  /** A second identity, for the isolation cases. Must also already exist. */
  otherIdentityId?: string
  /** Map a readable label to a row id the adapter's `id` column accepts. */
  sessionId?: (label: string) => string
}

const DEFAULT_IDS: Required<ComplianceIds> = {
  identityId: 'u',
  otherIdentityId: 'v',
  // A real hash, because that is what a session id is. The raw label ran the in-process stores against ids
  // every SQL dialect refuses, so the same suite was asserting a different contract on either side.
  sessionId: (label) => sha256(label),
}

/**
 * Compliance matrix for Session stores. Verifies hashed-key storage,
 * listing, GC purge of expired rows, and per-identity bulk delete.
 */
export function runSessionStoreCompliance(factory: () => Sessions.Store, ids: ComplianceIds = {}): void {
  const { identityId: OWNER, otherIdentityId: OTHER, sessionId: sid } = { ...DEFAULT_IDS, ...ids }
  describe('Session.IStore compliance', () => {
    it('every read path returns the field types the row type declares', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          aal: 2,
          absoluteExpiresAt: exp,
          actingAs: {
            expiresAt: exp,
            realIdentityId: OTHER,
            reason: 'support',
            startedAt: now,
          },
          createdAt: now,
          expiresAt: exp,
          factors: [{ completedAt: now, method: 'totp' }],
          fresh: true,
          id: sid('fidelity-1'),
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )
      // `create` returns void here, so every check below is a real read back
      // out of the store, which is the only kind that proves anything.
      const id = sid('fidelity-1')
      expectRow(await store.getByHash(id), SESSION_FIELDS, SESSION_KEYS, 'getByHash')
      for (const row of await store.listByIdentity(OWNER)) {
        expectRow(row, SESSION_FIELDS, SESSION_KEYS, 'listByIdentity')
      }
      expectRow(await store.update(id, { fresh: false }), SESSION_FIELDS, SESSION_KEYS, 'update')
    })

    it('update moves updatedAt', async () => {
      const store = factory()
      const now = new Date()
      await store.create(
        sessionInput({
          absoluteExpiresAt: new Date(now.getTime() + 600_000),
          aal: 1,
          createdAt: now,
          expiresAt: new Date(now.getTime() + 60_000),
          factors: [],
          fresh: true,
          id: sid('touch-1'),
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )
      const before = await store.getByHash(sid('touch-1'))
      await new Promise((r) => setTimeout(r, 25))

      // Exposed but frozen would be worse than absent: a caller reading it to find the last write would
      // be told every session was untouched since it was minted.
      const after = await store.update(sid('touch-1'), { fresh: false })
      expect(after.updatedAt.getTime()).toBeGreaterThan(before.updatedAt.getTime())
    })

    it('create + getByHash roundtrip uses the row id directly', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const session = sessionInput({
        id: sid('hash-1'),
        identityId: OWNER,
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      })
      await store.create(session)
      // Nullable columns the store fills with `null` are extra keys on the
      // returned row, so assert the caller-provided fields are a subset.
      expect(await store.getByHash(sid('hash-1'))).toMatchObject(session)
    })

    it('a create on an id already stored is refused, not an overwrite', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const first = sessionInput({
        aal: 1,
        absoluteExpiresAt: exp,
        createdAt: now,
        expiresAt: exp,
        factors: [],
        fresh: true,
        id: sid('dup-1'),
        identityId: OWNER,
        kind: 'user',
        rotatedAt: now,
      })
      await store.create(first)

      // The id is the caller's token hash. Taking the second write as an update would hand whoever still
      // holds the first token a session it never opened, at whatever AAL the second one asked for.
      await expect(store.create({ ...first, aal: 2 })).rejects.toMatchObject({ code: 'AUTH_ALREADY_EXISTS' })
      expect((await store.getByHash(sid('dup-1')))?.aal).toBe(1)
    })

    it('refuses a session it could not read back', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const ok = sessionInput({
        aal: 1,
        absoluteExpiresAt: exp,
        createdAt: now,
        expiresAt: exp,
        factors: [],
        fresh: true,
        id: sid('unreadable'),
        identityId: OWNER,
        kind: 'user',
        rotatedAt: now,
      })
      const invalid = { code: 'AUTH_INVALID_PARAMETERS' }

      // The redis reader rejects an unknown kind and an out-of-range aal outright, so a store that takes
      // the write hands its caller a sid every later read answers AUTH_SESSION_REVOKED for: a cookie for a
      // session that was never readable. The casts are the point — no compiler lets these through, and the
      // guard is what a JS caller and a dynamic patch still meet.
      await expect(store.create({ ...ok, kind: 'not-a-kind' as Sessions.Kind })).rejects.toMatchObject(invalid)
      await expect(store.create({ ...ok, aal: 99 as Sessions.AAL })).rejects.toMatchObject(invalid)
      await expect(store.create({ ...ok, tenantId: '' })).rejects.toMatchObject(invalid)

      await store.create(ok)
      await expect(store.update(sid('unreadable'), { aal: 99 as Sessions.AAL })).rejects.toMatchObject(invalid)
      // The refused patch left the row alone rather than half-writing it.
      expect((await store.getByHash(sid('unreadable'))).aal).toBe(1)
    })

    it('update cannot move a session onto another id', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          aal: 1,
          absoluteExpiresAt: exp,
          createdAt: now,
          expiresAt: exp,
          factors: [],
          fresh: true,
          id: sid('pinned'),
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )

      // `id` is the hash of the token in the caller's cookie, and `Partial<Me>` lets a patch name it. Moving
      // the row leaves that cookie reaching nothing and the session answering to a hash it never issued, so
      // the patch is ignored rather than refused: `update` is the refresh path and must stay a no-op here.
      const patched = await store.update(sid('pinned'), { fresh: false, id: sid('moved') })

      expect(patched.id).toBe(sid('pinned'))
      expect(patched.fresh).toBe(false)
      await expect(store.getByHash(sid('pinned'))).resolves.toBeTruthy()
      await expect(store.getByHash(sid('moved'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('a session repointed at another identity follows its new owner', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          aal: 1,
          absoluteExpiresAt: exp,
          createdAt: now,
          expiresAt: exp,
          factors: [],
          fresh: true,
          id: sid('repoint'),
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )
      await store.update(sid('repoint'), { identityId: OTHER })

      // The SQL stores filter a column and redis keeps a per-identity set, so nothing but the contract makes
      // the two agree. A session left behind in the old owner's index is one "sign out everywhere" misses.
      expect((await store.listByIdentity(OTHER)).map((r) => r.id)).toContain(sid('repoint'))
      expect((await store.listByIdentity(OWNER)).map((r) => r.id)).not.toContain(sid('repoint'))

      await store.deleteAllForIdentity(OTHER)
      await expect(store.getByHash(sid('repoint'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('factors and actingAs come back as real Dates, not the strings a JSON column stores', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          absoluteExpiresAt: exp,
          actingAs: { expiresAt: exp, realIdentityId: 'admin-1', reason: 'support', startedAt: now },
          aal: 2,
          createdAt: now,
          expiresAt: exp,
          factors: [{ completedAt: now, method: 'password' }],
          fresh: true,
          id: sid('json-dates'),
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )

      // Same JSON-column hazard as `providers[].addedAt`: an impersonation
      // window is read as `expiresAt.getTime() < Date.now()`, which on a string
      // is a TypeError rather than an expiry check.
      const back = await store.getByHash(sid('json-dates'))
      expect(back?.factors[0]?.completedAt).toBeInstanceOf(Date)
      expect(back?.factors[0]?.completedAt.getTime()).toBe(now.getTime())
      expect(back?.actingAs?.startedAt).toBeInstanceOf(Date)
      expect(back?.actingAs?.expiresAt).toBeInstanceOf(Date)
      expect(back?.actingAs?.expiresAt.getTime()).toBe(exp.getTime())
    })

    it('deleteAllForIdentities answers every session it swept', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const mk = (id: string, identityId: string) =>
        sessionInput({
          id: sid(id),
          identityId,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: now,
          rotatedAt: now,
          expiresAt: exp,
          absoluteExpiresAt: exp,
          fresh: true,
        })
      await store.create(mk('bulk-1', OWNER))
      await store.create(mk('bulk-2', OWNER))
      await store.create(mk('bulk-3', OTHER))

      // One entry per session removed, not per identity named: the facet emits an event from each.
      const gone = await store.deleteAllForIdentities([OWNER, OTHER, ABSENT])

      expect(gone.map((s) => s.id).sort()).toEqual([sid('bulk-1'), sid('bulk-2'), sid('bulk-3')].sort())
      expect(gone.every((s) => s.identityId === OWNER || s.identityId === OTHER)).toBe(true)
      expect(await store.listByIdentity(OWNER)).toEqual([])
      expect(await store.listByIdentity(OTHER)).toEqual([])
    })

    it('deleteMany answers only the sessions it removed', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const mk = (id: string) =>
        sessionInput({
          id: sid(id),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: now,
          rotatedAt: now,
          expiresAt: exp,
          absoluteExpiresAt: exp,
          fresh: true,
        })
      await store.create(mk('many-1'))
      await store.create(mk('many-2'))

      const gone = await store.deleteMany([sid('many-1'), sid('many-absent'), sid('many-2')])

      expect(gone.map((s) => s.id).sort()).toEqual([sid('many-1'), sid('many-2')].sort())
      expect(gone.every((s) => s.identityId === OWNER)).toBe(true)
      await expect(store.getByHash(sid('many-1'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(store.getByHash(sid('many-2'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      // The identity index has to go with the rows, or a revoked session is still listed as a device.
      expect(await store.listByIdentity(OWNER)).toEqual([])
    })

    it('a bulk call with no ids touches nothing', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          id: sid('bulk0'),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: now,
          rotatedAt: now,
          expiresAt: exp,
          absoluteExpiresAt: exp,
          fresh: true,
        }),
      )

      // These two are the widest destructive reach in the store, and an empty list is what a caller
      // holding no ids passes. A sweep with nothing to sweep is a no-op, never a wipe.
      expect(await store.deleteAllForIdentities([])).toEqual([])
      expect(await store.deleteMany([])).toEqual([])
      await expect(store.getByHash(sid('bulk0'))).resolves.toBeTruthy()
    })

    it('listByIdentity returns only sessions of the requested identity', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      }
      await store.create(sessionInput({ id: sid('u-1'), identityId: OWNER, ...base }))
      await store.create(sessionInput({ id: sid('u-2'), identityId: OWNER, ...base }))
      await store.create(sessionInput({ id: sid('v-1'), identityId: OTHER, ...base }))
      const us = await store.listByIdentity(OWNER)
      expect(us).toHaveLength(2)
    })

    it('deleteAllForIdentity wipes every session for the identity', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      }
      await store.create(sessionInput({ id: sid('a'), identityId: OWNER, ...base }))
      await store.create(sessionInput({ id: sid('b'), identityId: OWNER, ...base }))
      await store.deleteAllForIdentity(OWNER)
      expect(await store.listByIdentity(OWNER)).toHaveLength(0)
    })

    it('listByIdentity narrows to one tenant, and a global session is not in it', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      }
      await store.create(sessionInput({ id: sid('t-a'), identityId: OWNER, tenantId: 'tenant-a', ...base }))
      await store.create(sessionInput({ id: sid('t-b'), identityId: OWNER, tenantId: 'tenant-b', ...base }))
      await store.create(sessionInput({ id: sid('t-g'), identityId: OWNER, tenantId: null, ...base }))

      // Identities are global, so all three hang off one id. Unscoped sees them
      // all, which is every existing caller's behaviour and does not change.
      expect(await store.listByIdentity(OWNER)).toHaveLength(3)
      expect(await store.listByIdentity(OWNER, {})).toHaveLength(3)

      const a = await store.listByIdentity(OWNER, { tenantId: 'tenant-a' })
      expect(a.map((r) => r.id)).toEqual([sid('t-a')])
      const b = await store.listByIdentity(OWNER, { tenantId: 'tenant-b' })
      expect(b.map((r) => r.id)).toEqual([sid('t-b')])
      expect(await store.listByIdentity(OWNER, { tenantId: 'tenant-none' })).toEqual([])
    })

    it('deleteAllForIdentity scoped to a tenant leaves the identity signed in elsewhere', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      }
      await store.create(sessionInput({ id: sid('d-a'), identityId: OWNER, tenantId: 'tenant-a', ...base }))
      await store.create(sessionInput({ id: sid('d-b'), identityId: OWNER, tenantId: 'tenant-b', ...base }))
      await store.create(sessionInput({ id: sid('d-g'), identityId: OWNER, tenantId: null, ...base }))

      await store.deleteAllForIdentity(OWNER, { tenantId: 'tenant-a' })

      // Survivors are reachable by every route, not merely still on disk: an
      // index the scoped delete dropped wholesale would leave them alive and
      // impossible to sign out.
      expect((await store.listByIdentity(OWNER)).map((r) => r.id).sort()).toEqual([sid('d-b'), sid('d-g')].sort())
      await expect(store.getByHash(sid('d-b'))).resolves.toBeTruthy()
      await expect(store.getByHash(sid('d-a'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })

      await store.deleteAllForIdentity(OWNER)
      expect(await store.listByIdentity(OWNER)).toEqual([])
    })

    it('gc purges sessions with expiresAt or absoluteExpiresAt past now', async () => {
      const store = factory()
      const nowMs = Date.now()
      await store.create(
        sessionInput({
          id: sid('expired'),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: new Date(nowMs - 100_000),
          rotatedAt: new Date(nowMs - 100_000),
          expiresAt: new Date(nowMs - 1),
          absoluteExpiresAt: new Date(nowMs - 1),
          fresh: false,
        }),
      )
      await store.create(
        sessionInput({
          id: sid('live'),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: new Date(nowMs),
          rotatedAt: new Date(nowMs),
          expiresAt: new Date(nowMs + 60_000),
          absoluteExpiresAt: new Date(nowMs + 60_000),
          fresh: true,
        }),
      )
      const r = await store.gc(nowMs)
      expect(r.deleted).toBe(1)
      await expect(store.getByHash(sid('expired'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(store.getByHash(sid('live'))).resolves.toBeTruthy()
    })

    /** The cutoff comes from the caller, and the implementations disagreed about a number that is not one:
     *  `x < Infinity` is true for every row, so memory and redis swept every session including the live
     *  ones, while `x < NaN` is false for every row, so the same call on another dialect reported
     *  `deleted: 0` and swept nothing. */
    it('gc refuses a cutoff that is not a finite timestamp, and sweeps nothing when it does', async () => {
      const store = factory()
      const nowMs = Date.now()
      await store.create(
        sessionInput({
          absoluteExpiresAt: new Date(nowMs + 60_000),
          aal: 1,
          createdAt: new Date(nowMs),
          expiresAt: new Date(nowMs + 60_000),
          factors: [],
          fresh: true,
          id: sid('gcbad'),
          identityId: OWNER,
          kind: 'user',
          rotatedAt: new Date(nowMs),
        }),
      )
      for (const cutoff of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
        await expect(store.gc(cutoff)).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      }
      await expect(store.getByHash(sid('gcbad'))).resolves.toBeTruthy()
    })

    // These two methods had NO cross-adapter coverage. Both confirmed
    // divergences (error code, implicit rotatedAt) lived here.

    it('getByHash raises for an unknown id', async () => {
      await expect(factory().getByHash(sid('nope'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('update merges the patch and persists it', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          id: sid('u-1'), identityId: OWNER, kind: 'user', aal: 1, factors: [],
          createdAt: now, rotatedAt: now, expiresAt: exp, absoluteExpiresAt: exp, fresh: true,
        }),
      )
      const updated = await store.update(sid('u-1'), { fresh: false })
      expect(updated.fresh).toBe(false)
      expect(await store.getByHash(sid('u-1'))).toMatchObject({ fresh: false })
    })

    it('update does NOT mutate fields the caller did not patch', async () => {
      const store = factory()
      const rotated = new Date(Date.now() - 600_000)
      const exp = new Date(Date.now() + 60_000)
      await store.create(
        sessionInput({
          id: sid('u-1'), identityId: OWNER, kind: 'user', aal: 1, factors: [],
          createdAt: rotated, rotatedAt: rotated, expiresAt: exp, absoluteExpiresAt: exp, fresh: true,
        }),
      )
      const updated = await store.update(sid('u-1'), { fresh: false })
      // rotatedAt feeds the freshness gate — a store must never move it implicitly.
      expect(updated.rotatedAt.getTime()).toBe(rotated.getTime())
      expect(updated.createdAt.getTime()).toBe(rotated.getTime())
    })

    it('update leaves a field alone when the patch carries an explicit undefined', async () => {
      const store = factory()
      const id = sid('explicit-undefined')
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          aal: 1,
          absoluteExpiresAt: exp,
          createdAt: now,
          csrfHash: 'csrf-abc',
          expiresAt: exp,
          factors: [],
          fresh: true,
          id,
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )
      // `{ csrfHash: maybeToken }` with nothing to say means "leave it alone".
      // Clearing it here would silently switch double-submit CSRF off for the
      // session, which is exactly the kind of change nobody goes looking for.
      await store.update(id, { csrfHash: undefined })
      expect((await store.getByHash(id))?.csrfHash).toBe('csrf-abc')
    })

    it('a guest session round-trips with a null identityId', async () => {
      const store = factory()
      const id = sid('guest-session')
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          aal: 1,
          absoluteExpiresAt: exp,
          createdAt: now,
          expiresAt: exp,
          factors: [],
          fresh: true,
          id,
          identityId: null,
          kind: 'guest',
          rotatedAt: now,
        }),
      )
      const got = await store.getByHash(id)
      expect(got?.identityId).toBeNull()
      // It belongs to no identity, so it must not surface in anyone's list.
      expect((await store.listByIdentity(OWNER)).map((x) => x.id)).not.toContain(id)
    })

    it('update on an unknown id throws AUTH_SESSION_REVOKED', async () => {
      await expect(factory().update(sid('nope'), { fresh: false })).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })

    it('delete removes the row; deleting an unknown id is a silent no-op', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          id: sid('d-1'), identityId: OWNER, kind: 'user', aal: 1, factors: [],
          createdAt: now, rotatedAt: now, expiresAt: exp, absoluteExpiresAt: exp, fresh: true,
        }),
      )
      await store.delete(sid('d-1'))
      await expect(store.getByHash(sid('d-1'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(store.delete(sid('nope'))).resolves.toBeUndefined()
    })
  })
}

/** Compliance matrix for Credential stores: create, the `findById` and `findByHashedSecret` semantics that keep
 *  a revoked row distinct from a missing one, `rotate`'s optimistic lock, and `deleteByKind` cleanup. */
export function runCredentialStoreCompliance(factory: () => Credential.Store, ids: ComplianceIds = {}): void {
  const { identityId: OWNER } = { ...DEFAULT_IDS, ...ids }
  describe('Credential.IStore compliance', () => {
    it('every read path returns the field types the row type declares', async () => {
      const store = factory()
      const created = await store.create(
        credentialInput({
          expiresAt: new Date(Date.now() + 60_000),
          identityId: OWNER,
          kind: 'password',
          metadata: {},
          secret: 'hashed-pw',
        }),
        {},
      )
      expectRow(created, CREDENTIAL_FIELDS, CREDENTIAL_KEYS, 'create')
      expectRow(await store.findById(created.id, {}), CREDENTIAL_FIELDS, CREDENTIAL_KEYS, 'findById')
      expectRow(
        await store.findByHashedSecret('hashed-pw', 'password', {}),
        CREDENTIAL_FIELDS, CREDENTIAL_KEYS,
        'findByHashedSecret',
      )
      for (const row of await store.listByIdentity(OWNER, 'password', {})) {
        expectRow(row, CREDENTIAL_FIELDS, CREDENTIAL_KEYS, 'listByIdentity')
      }
      expectRow(
        await store.rotate(created.id, 'rotated-pw', created.version, {}),
        CREDENTIAL_FIELDS, CREDENTIAL_KEYS,
        'rotate',
      )
      expectRow(await store.patchMetadata(created.id, { seen: 1 }, {}), CREDENTIAL_FIELDS, CREDENTIAL_KEYS, 'patchMetadata')
      // `revokedAt` is the only date that is null until it is not.
      const revoked = await store.revoke(created.id, {})
      expectRow(revoked, CREDENTIAL_FIELDS, CREDENTIAL_KEYS, 'revoke')
      expect(revoked?.revokedAt).toBeInstanceOf(Date)
    })

    it('every write that touches the row moves updatedAt', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'password', metadata: {}, secret: 'touch-pw' }),
        {},
      )
      await new Promise((r) => setTimeout(r, 25))

      const rotated = await store.rotate(c.id, 'touch-pw-2', c.version, {})
      expect(rotated.updatedAt.getTime()).toBeGreaterThan(c.updatedAt.getTime())

      await new Promise((r) => setTimeout(r, 25))
      const patched = await store.patchMetadata(c.id, { seen: 1 }, {})
      expect(patched.updatedAt.getTime()).toBeGreaterThan(rotated.updatedAt.getTime())

      await new Promise((r) => setTimeout(r, 25))
      const gone = await store.revoke(c.id, {})
      expect(gone.updatedAt.getTime()).toBeGreaterThan(patched.updatedAt.getTime())
    })

    it('create stamps id + version=1; findById retrieves it', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'password', secret: 'hashed-pw', metadata: {} }),
        {},
      )
      expect(c.id).toBeTruthy()
      expect(c.version).toBe(1)
      const got = await store.findById(c.id, {})
      expect(got?.secret).toBe('hashed-pw')
    })

    it('create refuses a second password for one identity', async () => {
      const store = factory()
      await store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'hashed-pw' }), {})

      // `PasswordsImpl.set` deletes then creates, so this rule is the only thing between a delete that
      // did not happen and two password rows that authenticate just as well as each other.
      await expect(
        store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'second-pw' }), {}),
      ).rejects.toMatchObject({ code: 'AUTH_ALREADY_EXISTS' })
    })

    it('create refuses the values its table constraints reject', async () => {
      const store = factory()
      const invalid = { code: 'AUTH_INVALID_PARAMETERS' }

      await expect(
        store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: '   ' }), {}),
      ).rejects.toMatchObject(invalid)
      await expect(
        store.create(credentialInput({ identityId: OWNER, kind: 'not-a-kind' as Credential.Kind, secret: 'k' }), {}),
      ).rejects.toMatchObject(invalid)
      // An empty tenant is a scope of its own, matching no global row and no named one either.
      await expect(
        store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k', tenantId: '' }), {}),
      ).rejects.toMatchObject(invalid)
      await expect(
        store.create(
          credentialInput({
            expiresAt: new Date(Date.now() - 60_000),
            identityId: OWNER,
            kind: 'api-key',
            secret: 'k',
          }),
          {},
        ),
      ).rejects.toMatchObject(invalid)
    })

    it('a credential row records who wrote it, from the ambient actor', async () => {
      const store = factory()
      const c = await withActor('op-4', () =>
        store.create(credentialInput({ identityId: OWNER, kind: 'password', metadata: {}, secret: 'hashed-pw' }), {}),
      )

      // `auth_credentials` declares the same two columns as the other tables;
      // a password row that cannot say who set it is the case that matters most.
      expect(c.createdBy).toBe('op-4')
      expect(c.updatedBy).toBe('op-4')
    })

    it('findByHashedSecret returns the freshest live row before falling back to revoked', async () => {
      const store = factory()
      const c1 = await store.create(
        credentialInput({
          identityId: OWNER,
          kind: 'magic-link',
          secret: 'hash',
          metadata: {},
          expiresAt: new Date(Date.now() + 60_000),
        }),
        {},
      )
      await store.revoke(c1.id, {})
      // Same secret hash, but fresh row.
      const c2 = await store.create(
        credentialInput({
          identityId: OWNER,
          kind: 'magic-link',
          secret: 'hash',
          metadata: {},
          expiresAt: new Date(Date.now() + 60_000),
        }),
        {},
      )
      const got = await store.findByHashedSecret('hash', 'magic-link', {})
      expect(got?.id).toBe(c2.id)
    })

    it('findByHashedSecret falls back to the revoked row when no live rows exist', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'hash-x', metadata: {} }),
        {},
      )
      await store.revoke(c.id, {})
      const got = await store.findByHashedSecret('hash-x', 'api-key', {})
      expect(got?.revokedAt).toBeTruthy()
    })

    it('listByIdentity filters by kind when one is named', async () => {
      const store = factory()
      await store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p' }), {})
      await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k' }), {})
      const keys = await store.listByIdentity(OWNER, 'api-key', {})
      expect(keys.map((c) => c.kind)).toEqual(['api-key'])
      // A null kind is "every kind", not "no kind".
      expect((await store.listByIdentity(OWNER, null, {})).length).toBeGreaterThanOrEqual(2)
    })

    it('rotate stamps lastUsedAt, because a rotation is a use', async () => {
      const store = factory()
      const c = await store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'old' }), {})
      expect(c.lastUsedAt).toBeNull()
      const rotated = await store.rotate(c.id, 'new', c.version, {})
      // An idle-credential reaper reads this to decide what to cull; leaving it
      // null reported a credential as never used right after its secret changed.
      expect(rotated.lastUsedAt).toBeInstanceOf(Date)
    })

    it('a tenant cannot read or write another tenant credential by id', async () => {
      const store = factory()
      const mine = await store.create(
        credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'tenant-secret' }),
        { tenantId: 'tenant-a' },
      )
      // Every method takes a TenantContext. One that is taken and ignored is
      // worse than one that is absent: the caller believes it is scoped.
      await expect(store.findById(mine.id, { tenantId: 'tenant-b' })).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(store.revoke(mine.id, { tenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
      await expect(store.delete(mine.id, { tenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
      await expect(store.rotate(mine.id, 'stolen', mine.version, { tenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      // Still there, still the original secret.
      expect((await store.findById(mine.id, { tenantId: 'tenant-a' }))?.secret).toBe('tenant-secret')
    })

    it('a global credential is invisible to a tenant-scoped caller', async () => {
      const store = factory()
      const global = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'g-hash' }), {})
      expect(global.tenantId).toBeNull()

      // A row belonging to no tenant must not authenticate one. No dialect admits it, because
      // `eq(tenant_id, $1)` never matches NULL, and memory has to agree; pinned here so the two
      // cannot answer differently.
      await expect(store.findById(global.id, { tenantId: 'tenant-a' })).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(store.findByHashedSecret('g-hash', 'api-key', { tenantId: 'tenant-a' })).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      expect(await store.listByIdentity(OWNER, 'api-key', { tenantId: 'tenant-a' })).toEqual([])
      // Reachable unscoped, which is what makes it global rather than orphaned.
      await expect(store.findById(global.id, {})).resolves.toBeTruthy()
    })

    it('an unscoped caller and the owning tenant both see the row', async () => {
      const store = factory()
      const c = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 's' }), {
        tenantId: 'tenant-a',
      })
      // Without this the isolation test above could pass by hiding every row.
      await expect(store.findById(c.id, {})).resolves.toBeTruthy()
      await expect(store.findById(c.id, { tenantId: 'tenant-a' })).resolves.toBeTruthy()
    })

    it('patchMetadata cannot rewrite another tenant row', async () => {
      const store = factory()
      const mine = await store.create(
        credentialInput({ identityId: OWNER, kind: 'api-key', metadata: { scope: 'read' }, secret: 'pm-secret' }),
        { tenantId: 'tenant-a' },
      )

      // A patch is a write like any other: a tenant that cannot read the row must not be able to rewrite
      // what it carries, an api-key's own scope included.
      await expect(store.patchMetadata(mine.id, { scope: 'admin' }, { tenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
      expect((await store.findById(mine.id, { tenantId: 'tenant-a' }))?.metadata).toEqual({ scope: 'read' })
    })

    it('deleteByKind sweeps only inside the calling tenant', async () => {
      const store = factory()
      const a = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'dk-a' }), {
        tenantId: 'tenant-a',
      })
      const b = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'dk-b' }), {
        tenantId: 'tenant-b',
      })

      // Answering what it removed is what makes this checkable: a sweep that reached across tenants would
      // hand back both rows, and one that reached nothing would hand back none.
      expect((await store.deleteByKind(OWNER, 'api-key', { tenantId: 'tenant-b' })).map((c) => c.id)).toEqual([b.id])
      await expect(store.findById(a.id, { tenantId: 'tenant-a' })).resolves.toBeTruthy()
    })

    it('deleteByKindAndPurpose sweeps only inside the calling tenant', async () => {
      const store = factory()
      const a = await store.create(
        credentialInput({ identityId: OWNER, kind: 'recovery', metadata: { purpose: 'password-reset' }, secret: 'rp-a' }),
        { tenantId: 'tenant-a' },
      )
      const b = await store.create(
        credentialInput({ identityId: OWNER, kind: 'recovery', metadata: { purpose: 'password-reset' }, secret: 'rp-b' }),
        { tenantId: 'tenant-b' },
      )

      const removed = await store.deleteByKindAndPurpose(OWNER, 'recovery', 'password-reset', { tenantId: 'tenant-b' })
      expect(removed.map((c) => c.id)).toEqual([b.id])
      await expect(store.findById(a.id, { tenantId: 'tenant-a' })).resolves.toBeTruthy()
    })

    it('rotate on an unknown id surfaces AUTH_STALE_WRITE, not an auth error', async () => {
      const store = factory()
      const c = await store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p' }), {})
      await store.delete(c.id, {})
      // A conditional write that matched no row reads the same to a SQL bridge
      // whether the id is gone or the version moved, and a caller can only do
      // one thing about either: re-read and decide again.
      await expect(store.rotate(c.id, 'x', 1, {})).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    it('rotate with mismatched version surfaces AUTH_STALE_WRITE', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'password', secret: 'h1', metadata: {} }),
        {},
      )
      await store.rotate(c.id, 'h2', c.version, {})
      await expect(store.rotate(c.id, 'h3', 1, {})).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    it('deleteByKind removes only credentials of that kind for an identity', async () => {
      const store = factory()
      await store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p', metadata: {} }), {})
      await store.create(credentialInput({ identityId: OWNER, kind: 'totp', secret: 't', metadata: {} }), {})
      const removed = await store.deleteByKind(OWNER, 'password', {})
      // The rows that went, so a caller can say how many factors it dropped
      // without a count query the delete already answered.
      expect(removed.map((c) => c.kind)).toEqual(['password'])
      const rest = await store.listByIdentity(OWNER, null, {})
      expect(rest.every((c) => c.kind !== 'password')).toBe(true)
    })

    it('deleteByKindAndPurpose removes only that purpose, leaving the rest of the kind alone', async () => {
      // `recovery` carries a dozen meanings at once, so this is the difference between retiring an
      // account's old reset token and voiding its MFA backup codes in the same call.
      const store = factory()
      await store.create(
        credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'r1', metadata: { purpose: 'password-reset' } }),
        {},
      )
      await store.create(
        credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'r2', metadata: { purpose: 'password-reset' } }),
        {},
      )
      await store.create(
        credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'b1', metadata: { purpose: 'mfa-backup-code' } }),
        {},
      )
      await store.create(credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'n1', metadata: {} }), {})

      const removed = await store.deleteByKindAndPurpose(OWNER, 'recovery', 'password-reset', {})

      expect(removed.map((c) => c.secret).sort()).toEqual(['r1', 'r2'])
      const left = await store.listByIdentity(OWNER, 'recovery', {})
      // The backup code survives, and so does a row carrying no purpose at all: a null metadata
      // path must not match the string being asked for.
      expect(left.map((c) => c.secret).sort()).toEqual(['b1', 'n1'])
    })

    it('every credential removal answers with what it removed', async () => {
      const store = factory()
      const a = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k1' }), {})
      const b = await store.create(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p1' }), {})

      const revoked = await store.revoke(a.id, {})
      expect(revoked?.id).toBe(a.id)
      expect(revoked?.revokedAt).toBeInstanceOf(Date)

      // The row as it was: once the delete lands there is nothing left to read.
      const deleted = await store.delete(b.id, {})
      expect(deleted?.id).toBe(b.id)
      await expect(store.findById(b.id, {})).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
    })

    it('revoke bumps the version, so a rotate already holding the old one loses', async () => {
      const store = factory()
      const c = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k-cas' }), {})

      expect((await store.revoke(c.id, {})).version).toBe(c.version + 1)
      await expect(store.rotate(c.id, 'stolen', c.version, {})).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    /** RFC 6749 section 10.4. Only the memory adapter had this, so on every SQL dialect a replayed refresh
     *  token left every sibling live while the caller was told the family was revoked. */
    describe('revokeFamily', () => {
      const oauth = (secret: string, familyId: string, generation: number) =>
        credentialInput({
          identityId: OWNER,
          kind: 'oauth',
          metadata: { accessToken: `at-${generation}`, familyId, generation, provider: 'oauth:x', sub: 's' },
          secret,
        })

    it('findByHashedSecret answers the freshest of several rows sharing a secret', async () => {
      const store = factory()
      const older = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'shared' }), {})
      await new Promise((r) => setTimeout(r, 30))
      const newer = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'shared' }), {})

      // Re-issuing a key leaves both rows live for a moment. Whole-second `created_at` makes "freshest"
      // a coin toss between them, and the loser is the key the caller was just handed.
      const found = await store.findByHashedSecret('shared', 'api-key', {})
      expect(found?.id).toBe(newer.id)
      expect(found?.id).not.toBe(older.id)
    })

    it('lists newest first, so the first live row is the newest one', async () => {
      const store = factory()
      const made: string[] = []
      for (const label of ['oldest', 'middle', 'newest']) {
        made.push((await store.create(credentialInput({ identityId: OWNER, kind: 'totp', secret: label }), {})).id)
        await new Promise((r) => setTimeout(r, 15))
      }

      // `passwords` rotates "the first live row" and `mfa.confirm` takes the first unconfirmed enrollment,
      // so insertion order here hands a user who restarted TOTP setup the QR they already abandoned.
      const listed = await store.listByIdentity(OWNER, 'totp', {})
      expect(listed.map((c) => c.secret)).toEqual(['newest', 'middle', 'oldest'])
      expect(listed[0]?.id).toBe(made[2])
    })

      it('revokes every live row of the family and answers how many moved', async () => {
        const store = factory()
        const first = await store.create(oauth('rt-1', 'fam-a', 1), {})
        const second = await store.create(oauth('rt-2', 'fam-a', 2), {})

        expect(await store.revokeFamily('fam-a', {})).toBe(2)
        expect((await store.findById(first.id, {}))?.revokedAt).toBeInstanceOf(Date)
        expect((await store.findById(second.id, {}))?.revokedAt).toBeInstanceOf(Date)
      })

      it('records who revoked the family', async () => {
        const store = factory()
        const row = await withActor('op-fam', () => store.create(oauth('rt-who', 'fam-who', 1), {}))

        await withActor('op-revoker', () => store.revokeFamily('fam-who', {}))
        // A family revocation is the breach response, so "who pulled the trigger" is the audit question.
        expect((await store.findById(row.id, {}))?.updatedBy).toBe('op-revoker')
      })

      it('spares another family and another kind', async () => {
        const store = factory()
        const target = await store.create(oauth('rt-3', 'fam-a', 1), {})
        const other = await store.create(oauth('rt-4', 'fam-b', 1), {})
        // The same familyId, so the kind is the only thing keeping it out.
        const key = await store.create(
          credentialInput({ identityId: OWNER, kind: 'api-key', metadata: { familyId: 'fam-a' }, secret: 'k-fam' }),
          {},
        )

        expect(await store.revokeFamily('fam-a', {})).toBe(1)
        expect((await store.findById(target.id, {}))?.revokedAt).toBeInstanceOf(Date)
        expect((await store.findById(other.id, {}))?.revokedAt).toBeNull()
        expect((await store.findById(key.id, {}))?.revokedAt).toBeNull()
      })

      it('a named tenant never reaches another tenant, nor a global row', async () => {
        const store = factory()
        const scoped = await store.create({ ...oauth('rt-5', 'fam-a', 1), tenantId: 'tenant-a' }, {})
        const global = await store.create(oauth('rt-6', 'fam-a', 1), {})

        expect(await store.revokeFamily('fam-a', { tenantId: 'tenant-b' })).toBe(0)
        expect((await store.findById(scoped.id, {}))?.revokedAt).toBeNull()
        expect((await store.findById(global.id, {}))?.revokedAt).toBeNull()
      })

      it('counts only what it moved, so a second call answers zero', async () => {
        const store = factory()
        await store.create(oauth('rt-7', 'fam-c', 1), {})

        expect(await store.revokeFamily('fam-c', {})).toBe(1)
        expect(await store.revokeFamily('fam-c', {})).toBe(0)
      })

      it('bumps the version, so the CAS a reuse race is about cannot still win', async () => {
        const store = factory()
        const row = await store.create(oauth('rt-8', 'fam-d', 1), {})

        await store.revokeFamily('fam-d', {})
        await expect(store.rotate(row.id, 'stolen', row.version, {})).rejects.toMatchObject({
          code: 'AUTH_STALE_WRITE',
        })
      })
    })

    it('a credential removal that matches no row raises, and a kind sweep answers an empty list', async () => {
      const store = factory()
      const gone = (await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k2' }), {})).id
      await store.delete(gone, {})

      await expect(store.revoke(gone, {})).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(store.delete(gone, {})).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      expect(await store.deleteByKind(OWNER, 'recovery', {})).toEqual([])
    })

    it('patchMetadata shallow-merges + bumps version atomically', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'totp', secret: 's', metadata: { confirmed: false, counter: 0 } }),
        {},
      )
      const next = await store.patchMetadata(c.id, { confirmed: true }, {})
      expect((next.metadata as { confirmed: boolean; counter: number }).confirmed).toBe(true)
      expect((next.metadata as { confirmed: boolean; counter: number }).counter).toBe(0)
      expect(next.version).toBe(c.version + 1)
    })

    /** Two dialects skipped the write and two materialised `{}`, so a NULL a caller branches on became an
     *  object on half the adapters. A patch that says nothing writes nothing. */
    it('patchMetadata leaves a null metadata null when the patch says nothing', async () => {
      const store = factory()
      const c = await store.create(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k-empty' }), {})
      expect(c.metadata).toBeNull()

      expect((await store.patchMetadata(c.id, {}, {})).metadata).toBeNull()
      expect((await store.patchMetadata(c.id, { unset: undefined }, {})).metadata).toBeNull()
    })

    it('patchMetadata leaves what is already there alone when the patch says nothing', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'api-key', metadata: { kept: 1 }, secret: 'k-keep' }),
        {},
      )

      expect((await store.patchMetadata(c.id, {}, {})).metadata).toEqual({ kept: 1 })
    })

    /** The compare-and-set a caller uses to make "read a value, decide, record the new one" one step.
     *  Unconditional it is two steps, and two callers that both read before either wrote both decide on
     *  the same stale value - which is how one TOTP code bought two step-ups. */
    it('patchMetadata with an expectedVersion refuses a row whose version has moved', async () => {
      const store = factory()
      const c = await store.create(
        credentialInput({ identityId: OWNER, kind: 'totp', metadata: { step: 1 }, secret: 's-cas' }),
        {},
      )
      const moved = await store.patchMetadata(c.id, { step: 2 }, {}, c.version)
      expect(moved.metadata).toEqual({ step: 2 })
      expect(moved.version).toBe(c.version + 1)

      // The stale version is the one the first caller already spent.
      await expect(store.patchMetadata(c.id, { step: 3 }, {}, c.version)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      // Refused means nothing was written, not written-then-reported.
      expect((await store.findById(c.id, {})).metadata).toEqual({ step: 2 })
    })

    /** A conditional write matches no row whether it is gone or a version behind, so the dialects cannot
     *  tell the two apart and all six answer the one code a caller can act on. */
    it('patchMetadata with an expectedVersion throws AUTH_STALE_WRITE for an unknown id', async () => {
      const store = factory()
      await expect(store.patchMetadata(authUuidV7(), { x: 1 }, {}, 1)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
    })

    // `patchMetadata` reads before it writes, in every adapter, so it can tell a row that is not there
    // from one whose version moved, and only the second is worth a retry. A caller handed
    // `AUTH_STALE_WRITE` for a missing id retries until it gives up.
    it('patchMetadata throws AUTH_CREDENTIAL_NOT_FOUND for an unknown id', async () => {
      const store = factory()
      await expect(store.patchMetadata(authUuidV7(), { x: 1 }, {})).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
    })
  })
}
