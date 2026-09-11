import { describe, expect, it } from 'vitest'
import { OPTIONAL_METHODS, OPTIONAL_SUPPORT, type ShippedAdapterName } from '../__compliance__/optional-support'
import { IamDrizzleAdapter } from '../drizzle'
import { IamFileAdapter } from '../file'
import { IamHttpAdapter } from '../http'
import { IamMemoryAdapter } from '../memory'
import { IamPrismaAdapter } from '../prisma'
import { IamRedisAdapter } from '../redis'

// Checks `OPTIONAL_SUPPORT`, the table `runAdapterCompliance` gates on, against the real prototypes.
// NOTE: a declared table (not instance probing) makes a dropped method fail here instead of skipping tests.
describe('the optional-method support matrix is what the adapters actually implement', () => {
  const OPTIONAL = OPTIONAL_METHODS

  const EXPECTED = OPTIONAL_SUPPORT

  // Read off prototypes, so no adapter needs its client/delegate doubles constructed.
  const ADAPTERS: Array<[ShippedAdapterName, object]> = [
    ['IamMemoryAdapter', IamMemoryAdapter.prototype],
    ['IamFileAdapter', IamFileAdapter.prototype],
    ['IamRedisAdapter', IamRedisAdapter.prototype],
    ['IamPrismaAdapter', IamPrismaAdapter.prototype],
    ['IamDrizzleAdapter', IamDrizzleAdapter.prototype],
    ['IamHttpAdapter', IamHttpAdapter.prototype],
  ]

  it.each(ADAPTERS)('%s implements exactly the optional methods recorded for it', (name, proto) => {
    const actual = Object.fromEntries(
      OPTIONAL.map((m) => [m, typeof (proto as Record<string, unknown>)[m] === 'function']),
    )
    expect({ name, ...actual }).toEqual({ name, ...EXPECTED[name] })
  })

  it('covers every adapter this package ships', () => {
    expect(ADAPTERS.map(([n]) => n).sort()).toEqual(Object.keys(EXPECTED).sort())
  })

  it('every method in the matrix is one a compliance suite actually branches on', async () => {
    // The other direction: a listed method nothing gates on is a row with nothing behind it.
    const read = (name: string) =>
      import('node:fs/promises').then((fs) =>
        fs.readFile(new URL(`../__compliance__/${name}`, import.meta.url), 'utf8'),
      )
    const src = (await read('compliance.ts')) + (await read('engine-capability.ts'))
    const gated = new Set([...src.matchAll(/supports\.([A-Za-z]+)\)/g)].map((m) => m[1]))
    const fallbacks = ['updateAssignmentScope', 'assignRoleMany', 'revokeRoleMany']
    expect([...gated].sort()).toEqual(
      [...OPTIONAL].filter((m) => m !== 'getSubjectGrantBoundary' && m !== 'withClient').sort(),
    )
    // `getSubjectGrantBoundary` (see `grant-expiry-vs-cache`, drizzle suites) and `withClient` (see the
    // `with-client` tests) have no engine fallback, so no compliance clause gates on them.
    expect(fallbacks.every((m) => gated.has(m))).toBe(true)
  })
})
