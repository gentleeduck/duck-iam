import { describe, expect, it } from 'vitest'
import type { Identities } from '~/core/identities/identities.types'
import { rowsWithLinks } from '../drizzle.rows'

describe('rowsWithLinks', () => {
  const link = { addedAt: new Date(0), addedBy: null, providerId: 'github', providerSub: '1' }
  const identity: Omit<Identities.Me, 'providers'> = {
    createdAt: new Date(0),
    createdBy: null,
    deletedAt: null,
    deletedBy: null,
    emailVerified: false,
    id: 'a',
    profile: { email: 'a@x', username: 'a' },
    updatedAt: new Date(0),
    updatedBy: null,
    version: 1,
  }

  it('folds the repeated row into one, and reads no rows as a miss', () => {
    expect(rowsWithLinks([])).toEqual([])
    expect(
      rowsWithLinks([
        { identity, link },
        { identity, link: { ...link, providerId: 'google' } },
      ]),
    ).toEqual([{ ...identity, providers: [link, { ...link, providerId: 'google' }] }])
  })

  it('answers an unlinked row with no logins rather than a null in the list', () => {
    expect(rowsWithLinks([{ identity, link: null }])).toEqual([{ ...identity, providers: [] }])
  })
})
