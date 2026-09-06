import { describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../drizzle'
import { IamFileAdapter } from '../file'
import { IamHttpAdapter } from '../http'
import { IamMemoryAdapter } from '../memory'
import { IamPrismaAdapter } from '../prisma'
import { IamRedisAdapter } from '../redis'

/**
 * Which optional adapter methods each adapter implements, pinned.
 *
 * `runAdapterCompliance` has nineteen tests that begin `if (!a.someMethod)` and
 * bow out. They now report as SKIPPED rather than passed - but a skip is still
 * silent about the thing that matters here: whether an adapter STOPPED
 * implementing a method it used to. Before this file, a refactor that dropped
 * `assignRoleMany` from the drizzle adapter would have turned five asserting
 * tests into five silent ones, and the suite would have got *greener*.
 *
 * So the support matrix is data, asserted directly. Adding a method to an
 * adapter turns one row red and the fix is to update the row; removing one does
 * the same. Either way the change is visible in a diff instead of in a test
 * count nobody reads.
 *
 * The counts in the header of `docs/TEST-INVENTORY.md` are the other reason
 * this exists: a vacuous pass is indistinguishable from a real one there.
 */
describe('the optional-method support matrix is what the adapters actually implement', () => {
  const OPTIONAL = [
    'getSubjectScopedRoles',
    'updateAssignmentScope',
    'getSubjectGrantBoundary',
    'assignRoleMany',
    'revokeRoleMany',
    'withClient',
  ] as const

  /** `true` where the adapter implements the method. */
  const EXPECTED: Record<string, Record<(typeof OPTIONAL)[number], boolean>> = {
    // Only drizzle carries the validity window, so it alone can answer a grant
    // boundary or batch through a transaction.
    IamDrizzleAdapter: {
      assignRoleMany: true,
      getSubjectGrantBoundary: true,
      getSubjectScopedRoles: true,
      revokeRoleMany: true,
      updateAssignmentScope: true,
      withClient: true,
    },
    IamFileAdapter: {
      assignRoleMany: false,
      getSubjectGrantBoundary: false,
      getSubjectScopedRoles: true,
      revokeRoleMany: false,
      updateAssignmentScope: true,
      withClient: false,
    },
    // http and redis do not implement `updateAssignmentScope`; the engine falls
    // back to revoke-then-assign for them.
    IamHttpAdapter: {
      assignRoleMany: false,
      getSubjectGrantBoundary: false,
      getSubjectScopedRoles: true,
      revokeRoleMany: false,
      updateAssignmentScope: false,
      withClient: false,
    },
    IamMemoryAdapter: {
      assignRoleMany: false,
      getSubjectGrantBoundary: false,
      getSubjectScopedRoles: true,
      revokeRoleMany: false,
      updateAssignmentScope: true,
      withClient: false,
    },
    IamPrismaAdapter: {
      assignRoleMany: false,
      getSubjectGrantBoundary: false,
      getSubjectScopedRoles: true,
      revokeRoleMany: false,
      updateAssignmentScope: true,
      withClient: true,
    },
    IamRedisAdapter: {
      assignRoleMany: false,
      getSubjectGrantBoundary: false,
      getSubjectScopedRoles: true,
      revokeRoleMany: false,
      updateAssignmentScope: false,
      withClient: false,
    },
  }

  // Read off the PROTOTYPES, so nothing has to be constructed. Every adapter
  // here needs a different set of doubles to instantiate - a redis client, a
  // prisma delegate map, drizzle's `ops` bag - and building six of those to ask
  // a question about method presence makes the test fail for reasons that have
  // nothing to do with the matrix. `typeof proto.m === 'function'` is also the
  // exact predicate `runAdapterCompliance` branches on.
  const ADAPTERS: Array<[string, object]> = [
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

  it('every method in the matrix is one the compliance suite actually guards on', async () => {
    // Keeps the matrix honest in the other direction: a method listed here that
    // no compliance test bows out on is a row with nothing behind it.
    const src = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../__compliance__/compliance.ts', import.meta.url), 'utf8'),
    )
    const guarded = new Set([...src.matchAll(/if \(!a\.([A-Za-z]+)\) \{/g)].map((m) => m[1]))
    // `getSubjectScopedRoles` is guarded once; the rest appear many times.
    expect([...guarded].sort()).toEqual([...OPTIONAL].sort())
  })
})
