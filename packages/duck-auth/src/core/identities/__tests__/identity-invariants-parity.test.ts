/**
 * The sibling of `session-invariants-parity.test.ts`, for the table that names the account. pg, mysql and
 * sqlite each declare five constraints over an identity and its provider links: both logins must be a
 * string that says something, each must fit its column, and neither half of a link may be blank. The
 * in-process store carried none of them, and neither did the facet, whose only check on a profile is a
 * byte cap — so a blank, missing, over-long or non-string login was written in dev and refused in
 * production, and a row holding one is not findable by the address it was supposed to carry.
 *
 * The case list is keyed by the dialect's own constraint names and checked against the schema, so a CHECK
 * added to SQL with no in-process counterpart fails here rather than going unnoticed.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Identities } from '~/core/identities/identities.types'
import { identityInput } from '~/test/store-inputs'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

const profile = (over: Record<string, unknown> = {}): Identities.ProfileMetadataBase =>
  Object.assign({ email: 'ada@example.com', username: 'ada' }, over)

/** A profile with one of the two logins simply absent, which the type forbids and a JSON column does not. */
function without(key: 'email' | 'username'): Identities.ProfileMetadataBase {
  const p = profile()
  Reflect.deleteProperty(p, key)
  return p
}

/** `version` is the store's to set and appears in no input, so nothing a caller can present breaks it. */
const NOT_CALLER_REACHABLE = ['chk_auth_identities_version']

/** Every way of breaking each constraint that a caller can present, keyed by the dialect's name for it. */
const VIOLATIONS: Record<string, Array<Partial<Identities.CreateInput<Identities.ProfileMetadataBase>>>> = {
  chk_auth_identities_email_length: [{ profile: profile({ email: `${'e'.repeat(315)}@x.com` }) }],
  chk_auth_identities_profile_shape: [
    { profile: profile({ email: '' }) },
    { profile: profile({ username: '' }) },
    { profile: profile({ email: 42 }) },
    { profile: profile({ username: ['ada'] }) },
    { profile: without('email') },
    { profile: without('username') },
  ],
  chk_auth_identities_username_length: [{ profile: profile({ username: 'n'.repeat(192) }) }],
  chk_auth_identity_providers_provider_not_blank: [{ providers: [{ providerId: '', providerSub: 'sub-1' }] }],
  chk_auth_identity_providers_sub_not_blank: [{ providers: [{ providerId: 'github', providerSub: '' }] }],
}

const declaredIn = (dialect: string): string[] =>
  [
    ...new Set(
      readFileSync(join(SRC, `adapters/drizzle/${dialect}/${dialect}.schema.ts`), 'utf8').match(/chk_auth_identit\w+/g),
    ),
  ].sort()

const covered = [...Object.keys(VIOLATIONS), ...NOT_CALLER_REACHABLE].sort()

describe('the in-process identity store enforces what every dialect CHECKs', () => {
  for (const dialect of ['pg', 'mysql', 'sqlite'] as const) {
    it(`${dialect} declares exactly the constraints this file accounts for`, () => {
      expect(declaredIn(dialect)).toEqual(covered)
    })
  }

  let store: Identities.Store<Identities.ProfileMetadataBase>

  beforeEach(() => {
    store = new MemoryAdapter<Identities.ProfileMetadataBase>().identities
  })

  it('accepts a row that breaks none of them', async () => {
    const created = await store.create(identityInput({ profile: profile(), providers: [] }))

    await expect(store.find({ email: 'ada@example.com' })).resolves.toMatchObject({ id: created.id })
  })

  for (const [name, violations] of Object.entries(VIOLATIONS)) {
    violations.forEach((violation, i) => {
      it(`create refuses ${name} (${i + 1}/${violations.length})`, async () => {
        await expect(
          store.create(identityInput({ profile: profile(), providers: [], ...violation })),
        ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      })

      if (violation.profile === undefined) return
      it(`update refuses ${name} (${i + 1}/${violations.length})`, async () => {
        const row = await store.create(identityInput({ profile: profile(), providers: [] }))

        // `profile` is one column on every dialect, so a patch that moves it is held to the same list.
        await expect(store.update(row.id, { profile: violation.profile }, row.version)).rejects.toMatchObject({
          code: 'AUTH_INVALID_PARAMETERS',
        })
      })
    })
  }

  for (const link of [
    { providerId: '', providerSub: 'sub-1' },
    { providerId: 'github', providerSub: '' },
  ]) {
    it(`link refuses ${link.providerId === '' ? 'a blank providerId' : 'a blank providerSub'}`, async () => {
      const row = await store.create(identityInput({ profile: profile(), providers: [] }))

      await expect(store.link(row.id, link)).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })
  }
})
