import { describe, expect, it } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import { withActor } from '~/core/actor'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import {
  CREDENTIAL_FIELDS,
  expectFieldTypes,
  IDENTITY_FIELDS,
  SESSION_FIELDS,
} from '~/test/type-fidelity'

/**
 * Compliance test matrix for Identity stores. Every shipped adapter (memory,
 * redis, drizzle, prisma) imports this and runs it against a fresh instance;
 * the same assertions guarantee behaviour parity across adapters.
 */
/**
 * An identity id that is guaranteed absent AND guaranteed acceptable to the
 * adapter's `id` column. A literal like `'no-such-id'` is neither: Postgres
 * stores identity ids as `uuid` and rejects it as malformed input long before
 * it can miss. Creating a row and erasing it borrows the store's own id shape.
 */
async function absentIdentityId<P extends Identities.ProfileMetadataBase>(
  store: Identities.Store<P>,
): Promise<string> {
  const doomed = await store.create(
    identityInput({ profile: profileOf<P>(`absent-${Date.now()}@x`, 'absent') }),
  )
  await store.erase(doomed.id)
  return doomed.id
}

/**
 * A profile literal for the suite's unbound `P`.
 *
 * The one assertion in this file, down from sixty-eight identical ones. Every
 * adapter instantiates this suite with `{ username, email }`, and the suite only
 * ever exercises those two keys - but inside a function generic over
 * `P extends ProfileMetadataBase`, `P` could be narrower than any literal, so
 * `identityInput<P>` refuses one. A caller that binds `P` to a concrete type
 * needs no cast at all; this exists solely because the suite cannot see which
 * type it was instantiated with.
 */
function profileOf<P>(email: string, username: string): P {
  return { email, username } as P
}

/** Same idea for session compliance, whose identity ids come from the caller. */
const ABSENT = '00000000-0000-4000-8000-000000000000'

/**
 * Optional store methods are checked with `ctx.skip()`, never a bare `return`.
 * A `return` reported a PASS for a test that executed nothing, so an adapter
 * that had quietly stopped implementing `withClient` looked identical in the
 * output to one that implemented it correctly. A skip says which is which.
 */
/**
 * `withClient` is the adapter's, not a facet's: one rebind puts every store on the caller's transaction,
 * because they share the one connection. An adapter with no transactional driver omits it by design.
 */
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
    /**
     * The row type says `Date`, `number`, `boolean`. A driver that hands back
     * the serialised form satisfies `tsc` all the same, because nothing
     * re-checks a value once it has crossed the driver boundary - it surfaces
     * in a caller as `deletedAt.getTime is not a function`, or silently, as a
     * comparison that does the wrong thing. Every read path is checked, not
     * just `create`: `create` builds the row in memory and may never have gone
     * near the database.
     */
    it('every read path returns the field types the row type declares', async () => {
      const store = factory()
      const created = await store.create(
        identityInput({
          profile: profileOf<P>('fidelity@x.com', 'fidelity'),
          providers: [{ addedAt: new Date(), providerId: 'password', providerSub: 'sub-1' }],
        }),
      )
      expectFieldTypes(created, IDENTITY_FIELDS, 'create')
      expectFieldTypes(await store.find({ id: created.id }), IDENTITY_FIELDS, 'findById')
      expectFieldTypes(
        await store.find({ providerId: 'password', providerSub: 'sub-1' }),
        IDENTITY_FIELDS,
        'findByProviderSub',
      )
      expectFieldTypes(
        await store.update(created.id, { emailVerified: true }, created.version),
        IDENTITY_FIELDS,
        'update',
      )
      const linked = await store.link(created.id, {
        addedAt: new Date(),
        providerId: 'authGoogle',
        providerSub: 'g-1',
      })
      expectFieldTypes(linked, IDENTITY_FIELDS, 'link')
      expectFieldTypes(await store.unlink(created.id, 'authGoogle'), IDENTITY_FIELDS, 'unlink')
      // A soft-deleted row is the one case with every nullable date populated.
      const deleted = await store.softDelete(created.id, 60_000)
      expectFieldTypes(deleted, IDENTITY_FIELDS, 'softDelete')
      expect(deleted?.deletedAt).toBeInstanceOf(Date)
      expectFieldTypes(await store.restore(created.id), IDENTITY_FIELDS, 'restore')
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

    /**
     * One rule for all three lifecycle writes: `null` means the id matched
     * nothing, and a throw means a row WAS matched and a named rule refused it.
     * Typing one of the three as though it cannot miss tells a caller which
     * outcome the author happened to remember, not which outcomes exist.
     */
    it('softDelete, restore and erase all answer null for an id that matched nothing', async () => {
      const store = factory()
      const gone = await absentIdentityId(store)

      expect(await store.softDelete(gone, 60_000)).toBeNull()
      expect(await store.restore(gone)).toBeNull()
      expect(await store.erase(gone)).toBeNull()
    })

    /**
     * `created_by` and `updated_by` have been columns on `auth_identities`
     * since 5.x with nothing in the package able to write them, so every row
     * carried NULL provenance no matter who did the write. These pin that an
     * ambient actor now reaches the column, and - just as important - that
     * `createdBy` is written once and never re-stamped by a later writer.
     */
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

    it('a hidden row keeps its provider login, so restore has nothing to refuse', async () => {
      const store = factory()
      const a = await store.create(identityInput({ profile: profileOf<P>('pa@x', 'pa') }))
      await store.link(a.id, { addedAt: new Date(), providerId: 'google', providerSub: 'sub-shared' })
      await store.softDelete(a.id, 60_000)

      // Unreadable, but not unclaimed: `findByProviderSub` hides the row while
      // `uq_auth_identity_providers_sub`, which is not partial, still holds the login.
      expect(await store.find({ providerId: 'google', providerSub: 'sub-shared' })).toBeNull()
      const b = await store.create(identityInput({ profile: profileOf<P>('pb@x', 'pb') }))
      await expect(
        store.link(b.id, { addedAt: new Date(), providerId: 'google', providerSub: 'sub-shared' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })

      // Letting B take it would end A's only way back, which is what the grace window promises not to do.
      expect((await store.restore(a.id))?.id).toBe(a.id)
      expect((await store.find({ providerId: 'google', providerSub: 'sub-shared' }))?.id).toBe(a.id)
    })

    it('findByEmail finds a created identity (identities are global)', async () => {
      const store = factory()
      await store.create(identityInput({ profile: profileOf<P>('shared@x', 'shared') }))
      expect(await store.find({ email: 'shared@x' })).not.toBeNull()
    })

    it('update with expectedVersion mismatch surfaces AUTH/STALE_WRITE', async () => {
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
      expect(await store.find({ id: i.id })).toBeNull()
      const restored = await store.restore(i.id)
      expect(restored?.id).toBe(i.id)
      await store.erase(i.id)
      expect(await store.find({ id: i.id })).toBeNull()
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
      // window that shut before it opened - the same state a row reaches by
      // simply sitting there, without the test having to wait for it.
      await store.softDelete(i.id, -1000)

      await expect(store.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
      // Still gone: a refused restore must not half-apply.
      expect(await store.find({ id: i.id })).toBeNull()
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

      expect((await store.restore(i.id))?.id).toBe(i.id)
      expect((await store.find({ email: 'a@x' }))?.id).toBe(i.id)
    })

    /**
     * Every dialect declares unique indexes on email and username, neither of them partial on
     * `deletedAt`. A store that admits a duplicate is holding state Postgres will not, and every test
     * that runs on it is asserting behaviour the real adapters do not have - so the rule belongs to
     * the contract, not to one adapter's implementation of it.
     */
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

    it('find matches any of the spellings it is given', async () => {
      const store = factory()
      const created = await store.create(identityInput({ profile: profileOf<P>('many@x', 'many') }))
      expect((await store.find({ email: ['nobody@x', 'many@x'] }))?.id).toBe(created.id)
    })

    it('find refuses an empty list of spellings rather than matching the first row', async () => {
      const store = factory()
      await store.create(identityInput({ profile: profileOf<P>('any@x', 'any') }))
      await expect(store.find({ email: [] })).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
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
      expect(await store.find({ providerId: 'oauth:authGoogle', providerSub: 'sub-1' })).toBeNull()
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

    /**
     * `providers` lives in a json/jsonb column, which stores a `Date` as a
     * string and hands back a string. `Identities.ProviderLink.addedAt` is
     * typed `Date`, so every read path has to revive it or the type is a lie
     * and callers get `addedAt.getTime is not a function`.
     *
     * Pinned on every read that can carry a link, and on the write that creates
     * one, because a reviver applied to three of four paths is the harder bug:
     * it works until the one call site nobody tested.
     */
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

    /**
     * The guard above counts hidden holders too, matching the address rule. Freeing the sub the moment
     * the row is hidden would let the next caller take the account and leave its owner no way back,
     * which is the one thing the grace window promises. Erase is what releases it.
     */
    it('a soft-deleted holder keeps its provider sub until it is erased', async () => {
      const store = factory()
      const first = await store.create(identityInput({ profile: profileOf<P>('fh1@x', 'fh1') }))
      const second = await store.create(identityInput({ profile: profileOf<P>('fh2@x', 'fh2') }))
      await store.link(first.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'freed-sub' })
      await store.softDelete(first.id, 60_000)

      // Unreadable and still claimed: the read side hides the row, the write side keeps refusing it.
      expect(await store.find({ providerId: 'oauth:authGoogle', providerSub: 'freed-sub' })).toBeNull()
      await expect(
        store.link(second.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'freed-sub' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })

      await store.erase(first.id)
      await store.link(second.id, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'freed-sub' })
      expect((await store.find({ providerId: 'oauth:authGoogle', providerSub: 'freed-sub' }))?.id).toBe(second.id)
    })

    it('softDelete on an already-hidden row answers null and leaves the deadline where it was', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('sd@x', 'sd') }))
      const first = await store.softDelete(i.id, 60_000)
      expect(first).not.toBeNull()

      // Re-stamping would push the purge deadline forward every time it was
      // called, so a row queued for hard deletion could be kept alive
      // indefinitely by repeating a delete that changes nothing.
      expect(await store.softDelete(i.id, 60_000)).toBeNull()
    })

    it('merging a row into itself is a no-op that returns the row, not a deletion', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: profileOf<P>('ss@x', 'ss') }))
      const merged = await store.merge(i.id, i.id)
      expect(merged?.id).toBe(i.id)
      // The reassignment loops run and then the "duplicate" is erased - which
      // is the survivor. A dedupe job that hands in the same id twice must not
      // delete the account it was asked to keep.
      expect(await store.find({ id: i.id })).not.toBeNull()
    })

    it('update leaves a field alone when the patch carries an explicit undefined', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({ emailVerified: true, profile: profileOf<P>('eu@x', 'eu') }),
      )
      // `{ profile: maybeProfile }` with nothing to say means "leave it alone",
      // never "clear the column" - which is what a bare spread would do.
      const next = await store.update(i.id, { profile: undefined }, i.version)
      expect(next.profile).toEqual(i.profile)
    })

    it('merge moves providers from dup into survivor + deletes dup', async () => {
      const store = factory()
      const survivor = await store.create(
        identityInput({
          profile: profileOf<P>('s@x', 's'),
          providers: [{ providerId: 'oauth:authGithub', providerSub: 'merge-sub', addedAt: new Date() }],
        }),
      )
      const dup = await store.create(
        identityInput({
          profile: profileOf<P>('d@x', 'd'),
          providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g', addedAt: new Date() }],
        }),
      )
      const merged = await store.merge(survivor.id, dup.id)
      // The survivor comes back from the write itself, already carrying the
      // union - a caller that needs it should not have to re-read.
      expect(merged?.id).toBe(survivor.id)
      expect(merged?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      const fresh = await store.find({ id: survivor.id })
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      expect(await store.find({ id: dup.id })).toBeNull()
    })

    it('merge writes nothing when either side is missing', async () => {
      const store = factory()
      const dup = await store.create(identityInput({ profile: profileOf<P>('md@x', 'md') }))
      const survivor = await store.create(identityInput({ profile: profileOf<P>('ms@x', 'ms') }))
      const gone = (await store.create(identityInput({ profile: profileOf<P>('mg@x', 'mg') })))
        .id
      await store.erase(gone)

      // A merge re-points the dup's credentials and sessions and then deletes
      // it. With one side missing that is not a merge, it is data loss - so
      // nothing is written and the caller is told plainly.
      expect(await store.merge(gone, dup.id)).toBeNull()
      expect(await store.find({ id: dup.id })).not.toBeNull()

      expect(await store.merge(survivor.id, gone)).toBeNull()
      expect(await store.find({ id: survivor.id })).not.toBeNull()
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
      expect(await store.find({ id: i.id })).toBeNull()
    })

    it('a write that matches no row answers null rather than reporting a change', async () => {
      const store = factory()
      // A real id whose row is gone - valid for every dialect's id column,
      // which a made-up string would not be.
      const gone = (await store.create(identityInput({ profile: profileOf<P>('g@x', 'g') }))).id
      await store.erase(gone)

      expect(await store.softDelete(gone, 60_000)).toBeNull()
      expect(await store.erase(gone)).toBeNull()
      expect(
        await store.link(gone, { addedAt: new Date(), providerId: 'oauth:authGoogle', providerSub: 'gone-sub' }),
      ).toBeNull()
      expect(await store.unlink(gone, 'oauth:authGoogle')).toBeNull()
      expect(await store.merge(gone, gone)).toBeNull()
    })
  })
}

/**
 * Row identifiers the session + credential matrices plant. The defaults are short
 * readable strings, which is all a permissive store needs. Adapters with a strict
 * schema override them: Postgres types `identity_id` as `uuid` behind a foreign
 * key, and constrains `auth_sessions.id` to exactly 64 chars, so the matrix has to
 * be handed ids that satisfy the real columns or it can never run there.
 */
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
  sessionId: (label) => label,
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
      // out of the store - which is the only kind that proves anything.
      const id = sid('fidelity-1')
      expectFieldTypes(await store.getByHash(id), SESSION_FIELDS, 'getByHash')
      for (const row of await store.listByIdentity(OWNER)) {
        expectFieldTypes(row, SESSION_FIELDS, 'listByIdentity')
      }
      expectFieldTypes(await store.update(id, { fresh: false }), SESSION_FIELDS, 'update')
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

    it('deleteAllForIdentities, when present, sweeps every named identity', async (ctx) => {
      const store = factory()
      // A store with no set-based form is complete without one; the facet loops.
      if (!store.deleteAllForIdentities) return ctx.skip()
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

      const result = await store.deleteAllForIdentities([OWNER, OTHER, ABSENT])

      expect(result.outcomes.map((o) => o.id)).toEqual([OWNER, OTHER, ABSENT])
      expect(result.applied).toBe(2)
      expect(result.outcomes[2]).toMatchObject({ ok: false, reason: 'not-found' })
      expect(await store.listByIdentity(OWNER)).toEqual([])
      expect(await store.listByIdentity(OTHER)).toEqual([])
    })

    it('deleteMany, when present, reports one outcome per session in input order', async (ctx) => {
      const store = factory()
      // A store with no set-based form is complete without one; the facet loops.
      if (!store.deleteMany) return ctx.skip()
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

      const result = await store.deleteMany([sid('many-1'), sid('many-absent'), sid('many-2')])

      expect(result.outcomes.map((o) => o.id)).toEqual([sid('many-1'), sid('many-absent'), sid('many-2')])
      expect(result.applied).toBe(2)
      expect(result.outcomes[1]).toMatchObject({ ok: false, reason: 'not-found' })
      expect(await store.getByHash(sid('many-1'))).toBeNull()
      expect(await store.getByHash(sid('many-2'))).toBeNull()
      // The identity index has to go with the rows, or a revoked session is still listed as a device.
      expect(await store.listByIdentity(OWNER)).toEqual([])
    })

    it('listByIdentities, when present, returns the union of the named identities and nothing else', async (ctx) => {
      const store = factory()
      if (!store.listByIdentities) return ctx.skip()
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
      await store.create(mk('union-1', OWNER))
      // An unnamed identity, or the read cannot be told apart from one that returns the whole table.
      await store.create(mk('union-2', OTHER))

      const rows = await store.listByIdentities([OWNER, ABSENT])

      expect(rows.map((r) => r.id)).toEqual([sid('union-1')])
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
      // all - that is every existing caller's behaviour and it does not change.
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
      expect(await store.getByHash(sid('d-b'))).not.toBeNull()
      expect(await store.getByHash(sid('d-a'))).toBeNull()

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
      expect(await store.getByHash(sid('expired'))).toBeNull()
      expect(await store.getByHash(sid('live'))).not.toBeNull()
    })

    // These two methods had NO cross-adapter coverage. Both confirmed
    // divergences (error code, implicit rotatedAt) lived here.

    it('getByHash returns null for an unknown id', async () => {
      expect(await factory().getByHash(sid('nope'))).toBeNull()
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
      expect(await store.getByHash(sid('d-1'))).toBeNull()
      await expect(store.delete(sid('nope'))).resolves.toBeUndefined()
    })
  })
}

/**
 * Compliance matrix for Credential stores. Covers upsert + findById +
 * findByHashedSecret semantics (revoked rows distinguished from missing),
 * rotate optimistic-lock, deleteByKind cleanup.
 */
export function runCredentialStoreCompliance(factory: () => Credential.Store, ids: ComplianceIds = {}): void {
  const { identityId: OWNER } = { ...DEFAULT_IDS, ...ids }
  describe('Credential.IStore compliance', () => {
    it('every read path returns the field types the row type declares', async () => {
      const store = factory()
      const created = await store.upsert(
        credentialInput({
          expiresAt: new Date(Date.now() + 60_000),
          identityId: OWNER,
          kind: 'password',
          metadata: {},
          secret: 'hashed-pw',
        }),
        {},
      )
      expectFieldTypes(created, CREDENTIAL_FIELDS, 'upsert')
      expectFieldTypes(await store.findById(created.id, {}), CREDENTIAL_FIELDS, 'findById')
      expectFieldTypes(
        await store.findByHashedSecret('hashed-pw', 'password', {}),
        CREDENTIAL_FIELDS,
        'findByHashedSecret',
      )
      for (const row of await store.listByIdentity(OWNER, 'password', {})) {
        expectFieldTypes(row, CREDENTIAL_FIELDS, 'listByIdentity')
      }
      expectFieldTypes(
        await store.rotate(created.id, 'rotated-pw', created.version, {}),
        CREDENTIAL_FIELDS,
        'rotate',
      )
      expectFieldTypes(await store.patchMetadata(created.id, { seen: 1 }, {}), CREDENTIAL_FIELDS, 'patchMetadata')
      // `revokedAt` is the only date that is null until it is not.
      const revoked = await store.revoke(created.id, {})
      expectFieldTypes(revoked, CREDENTIAL_FIELDS, 'revoke')
      expect(revoked?.revokedAt).toBeInstanceOf(Date)
    })

    it('upsert stamps id + version=1; findById retrieves it', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'password', secret: 'hashed-pw', metadata: {} }),
        {},
      )
      expect(c.id).toBeTruthy()
      expect(c.version).toBe(1)
      const got = await store.findById(c.id, {})
      expect(got?.secret).toBe('hashed-pw')
    })

    it('a credential row records who wrote it, from the ambient actor', async () => {
      const store = factory()
      const c = await withActor('op-4', () =>
        store.upsert(credentialInput({ identityId: OWNER, kind: 'password', metadata: {}, secret: 'hashed-pw' }), {}),
      )

      // `auth_credentials` declares the same two columns as the other tables;
      // a password row that cannot say who set it is the case that matters most.
      expect(c.createdBy).toBe('op-4')
      expect(c.updatedBy).toBe('op-4')
    })

    it('findByHashedSecret returns the freshest live row before falling back to revoked', async () => {
      const store = factory()
      const c1 = await store.upsert(
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
      const c2 = await store.upsert(
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
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'hash-x', metadata: {} }),
        {},
      )
      await store.revoke(c.id, {})
      const got = await store.findByHashedSecret('hash-x', 'api-key', {})
      expect(got?.revokedAt).toBeTruthy()
    })

    it('findByProviderSub locates an oauth credential and ignores other kinds', async () => {
      const store = factory()
      const oauth = await store.upsert(
        credentialInput({
          identityId: OWNER,
          kind: 'oauth',
          metadata: { provider: 'authGoogle', sub: 'psub-1' },
          secret: 'tok',
        }),
        {},
      )
      // A non-oauth row carrying the same marker metadata must not answer here:
      // matching on metadata alone would let any credential kind impersonate a
      // federated identity lookup.
      await store.upsert(
        credentialInput({
          identityId: OWNER,
          kind: 'api-key',
          metadata: { provider: 'authGoogle', sub: 'psub-1' },
          secret: 'key',
        }),
        {},
      )
      const found = await store.findByProviderSub('authGoogle', 'psub-1', {})
      expect(found?.id).toBe(oauth.id)
      expect(found?.kind).toBe('oauth')
      expect(await store.findByProviderSub('authGoogle', 'no-such-sub', {})).toBeNull()
    })

    it('listByIdentity filters by kind when one is named', async () => {
      const store = factory()
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p' }), {})
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k' }), {})
      const keys = await store.listByIdentity(OWNER, 'api-key', {})
      expect(keys.map((c) => c.kind)).toEqual(['api-key'])
      // A null kind is "every kind", not "no kind".
      expect((await store.listByIdentity(OWNER, null, {})).length).toBeGreaterThanOrEqual(2)
    })

    it('rotate stamps lastUsedAt, because a rotation is a use', async () => {
      const store = factory()
      const c = await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'old' }), {})
      expect(c.lastUsedAt).toBeNull()
      const rotated = await store.rotate(c.id, 'new', c.version, {})
      // An idle-credential reaper reads this to decide what to cull; leaving it
      // null reported a credential as never used right after its secret changed.
      expect(rotated.lastUsedAt).toBeInstanceOf(Date)
    })

    it('a tenant cannot read or write another tenant credential by id', async () => {
      const store = factory()
      const mine = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'tenant-secret' }),
        { tenantId: 'tenant-a' },
      )
      // Every method takes a TenantContext. One that is taken and ignored is
      // worse than one that is absent: the caller believes it is scoped.
      expect(await store.findById(mine.id, { tenantId: 'tenant-b' })).toBeNull()
      expect(await store.revoke(mine.id, { tenantId: 'tenant-b' })).toBeNull()
      expect(await store.delete(mine.id, { tenantId: 'tenant-b' })).toBeNull()
      await expect(store.rotate(mine.id, 'stolen', mine.version, { tenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      // Still there, still the original secret.
      expect((await store.findById(mine.id, { tenantId: 'tenant-a' }))?.secret).toBe('tenant-secret')
    })

    it('a global credential is invisible to a tenant-scoped caller', async () => {
      const store = factory()
      const global = await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'g-hash' }), {})
      expect(global.tenantId).toBeNull()

      // A row belonging to no tenant must not authenticate one. The memory
      // adapter used to admit it and called that "SQL parity"; no dialect ever
      // did, because `eq(tenant_id, $1)` never matches NULL. Pinned here so the
      // two cannot answer differently again.
      expect(await store.findById(global.id, { tenantId: 'tenant-a' })).toBeNull()
      expect(await store.findByHashedSecret('g-hash', 'api-key', { tenantId: 'tenant-a' })).toBeNull()
      expect(await store.listByIdentity(OWNER, 'api-key', { tenantId: 'tenant-a' })).toEqual([])
      // Reachable unscoped, which is what makes it global rather than orphaned.
      expect(await store.findById(global.id, {})).not.toBeNull()
    })

    it('an unscoped caller and the owning tenant both see the row', async () => {
      const store = factory()
      const c = await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 's' }), {
        tenantId: 'tenant-a',
      })
      // Without this the isolation test above could pass by hiding every row.
      expect(await store.findById(c.id, {})).not.toBeNull()
      expect(await store.findById(c.id, { tenantId: 'tenant-a' })).not.toBeNull()
    })

    it('rotate on an unknown id surfaces AUTH/STALE_WRITE, not an auth error', async () => {
      const store = factory()
      const c = await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p' }), {})
      await store.delete(c.id, {})
      // A conditional write that matched no row reads the same to a SQL bridge
      // whether the id is gone or the version moved, and a caller can only do
      // one thing about either: re-read and decide again.
      await expect(store.rotate(c.id, 'x', 1, {})).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    it('rotate with mismatched version surfaces AUTH/STALE_WRITE', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'password', secret: 'h1', metadata: {} }),
        {},
      )
      await store.rotate(c.id, 'h2', c.version, {})
      await expect(store.rotate(c.id, 'h3', 1, {})).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    it('deleteByKind removes only credentials of that kind for an identity', async () => {
      const store = factory()
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p', metadata: {} }), {})
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'totp', secret: 't', metadata: {} }), {})
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
      await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'r1', metadata: { purpose: 'password-reset' } }),
        {},
      )
      await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'r2', metadata: { purpose: 'password-reset' } }),
        {},
      )
      await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'b1', metadata: { purpose: 'mfa-backup-code' } }),
        {},
      )
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'recovery', secret: 'n1', metadata: {} }), {})

      const removed = await store.deleteByKindAndPurpose(OWNER, 'recovery', 'password-reset', {})

      expect(removed.map((c) => c.secret).sort()).toEqual(['r1', 'r2'])
      const left = await store.listByIdentity(OWNER, 'recovery', {})
      // The backup code survives, and so does a row carrying no purpose at all: a null metadata
      // path must not match the string being asked for.
      expect(left.map((c) => c.secret).sort()).toEqual(['b1', 'n1'])
    })

    it('every credential removal answers with what it removed', async () => {
      const store = factory()
      const a = await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k1' }), {})
      const b = await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p1' }), {})

      const revoked = await store.revoke(a.id, {})
      expect(revoked?.id).toBe(a.id)
      expect(revoked?.revokedAt).toBeInstanceOf(Date)

      // The row as it was: once the delete lands there is nothing left to read.
      const deleted = await store.delete(b.id, {})
      expect(deleted?.id).toBe(b.id)
      expect(await store.findById(b.id, {})).toBeNull()
    })

    it('revoke bumps the version, so a rotate already holding the old one loses', async () => {
      const store = factory()
      const c = await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k-cas' }), {})

      expect((await store.revoke(c.id, {}))?.version).toBe(c.version + 1)
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

      it('revokes every live row of the family and answers how many moved', async () => {
        const store = factory()
        const first = await store.upsert(oauth('rt-1', 'fam-a', 1), {})
        const second = await store.upsert(oauth('rt-2', 'fam-a', 2), {})

        expect(await store.revokeFamily('fam-a', {})).toBe(2)
        expect((await store.findById(first.id, {}))?.revokedAt).toBeInstanceOf(Date)
        expect((await store.findById(second.id, {}))?.revokedAt).toBeInstanceOf(Date)
      })

      it('spares another family and another kind', async () => {
        const store = factory()
        const target = await store.upsert(oauth('rt-3', 'fam-a', 1), {})
        const other = await store.upsert(oauth('rt-4', 'fam-b', 1), {})
        // The same familyId, so the kind is the only thing keeping it out.
        const key = await store.upsert(
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
        const scoped = await store.upsert({ ...oauth('rt-5', 'fam-a', 1), tenantId: 'tenant-a' }, {})
        const global = await store.upsert(oauth('rt-6', 'fam-a', 1), {})

        expect(await store.revokeFamily('fam-a', { tenantId: 'tenant-b' })).toBe(0)
        expect((await store.findById(scoped.id, {}))?.revokedAt).toBeNull()
        expect((await store.findById(global.id, {}))?.revokedAt).toBeNull()
      })

      it('counts only what it moved, so a second call answers zero', async () => {
        const store = factory()
        await store.upsert(oauth('rt-7', 'fam-c', 1), {})

        expect(await store.revokeFamily('fam-c', {})).toBe(1)
        expect(await store.revokeFamily('fam-c', {})).toBe(0)
      })

      it('bumps the version, so the CAS a reuse race is about cannot still win', async () => {
        const store = factory()
        const row = await store.upsert(oauth('rt-8', 'fam-d', 1), {})

        await store.revokeFamily('fam-d', {})
        await expect(store.rotate(row.id, 'stolen', row.version, {})).rejects.toMatchObject({
          code: 'AUTH_STALE_WRITE',
        })
      })
    })

    it('a credential removal that matches no row answers null or an empty list', async () => {
      const store = factory()
      const gone = (await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k2' }), {})).id
      await store.delete(gone, {})

      expect(await store.revoke(gone, {})).toBeNull()
      expect(await store.delete(gone, {})).toBeNull()
      expect(await store.deleteByKind(OWNER, 'recovery', {})).toEqual([])
    })

    it('patchMetadata shallow-merges + bumps version atomically', async () => {
      const store = factory()
      const c = await store.upsert(
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
      const c = await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k-empty' }), {})
      expect(c.metadata).toBeNull()

      expect((await store.patchMetadata(c.id, {}, {})).metadata).toBeNull()
      expect((await store.patchMetadata(c.id, { unset: undefined }, {})).metadata).toBeNull()
    })

    it('patchMetadata leaves what is already there alone when the patch says nothing', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'api-key', metadata: { kept: 1 }, secret: 'k-keep' }),
        {},
      )

      expect((await store.patchMetadata(c.id, {}, {})).metadata).toEqual({ kept: 1 })
    })

    // `patchMetadata` reads before it writes, in every adapter, so it can tell a row that is not there
    // from one whose version moved - and only the second is worth a retry. A caller handed
    // `AUTH_STALE_WRITE` for a missing id retries until it gives up.
    it('patchMetadata throws AUTH/CREDENTIAL_NOT_FOUND for an unknown id', async () => {
      const store = factory()
      await expect(store.patchMetadata(authUuidV7(), { x: 1 }, {})).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
    })
  })
}
