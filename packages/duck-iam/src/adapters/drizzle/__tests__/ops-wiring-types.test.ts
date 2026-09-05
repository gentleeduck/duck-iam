import { and, eq, isNull, or } from 'drizzle-orm'
import { describe, expect, it } from 'vitest'
import type { IamDrizzle } from '../index'

/**
 * The wiring in `IamDrizzleAdapter`'s own `@example` - `ops: { eq, and }`, with
 * drizzle's operators passed straight through - did not compile against
 * drizzle.
 *
 * `ops.eq` was declared `(col: unknown, val: unknown) => unknown` and
 * `ops.isNull` as `(col: unknown) => SQLWrapper`. Under `strictFunctionTypes` a
 * parameter is contravariant, so an `unknown` parameter is the *narrowest*
 * thing a caller can satisfy, not the widest: drizzle's real `eq` and `isNull`,
 * whose parameters are `Column` / `SQLWrapper`, are not assignable to them.
 * Every caller had to find that out at their own keyboard and write a
 * re-widening wrapper with a cast in it - which the package's own e2e suite
 * did, and documented as a finding.
 *
 * This is a type test. The `satisfies` below is the assertion and it is checked
 * by `tsc`, not by the runtime body; the `it` exists so the file is a suite
 * rather than a thing that silently never runs. A regression here is a
 * compile error in this file, which is exactly where a caller would hit it.
 */
describe('drizzle-orm operators satisfy the adapter ops bundle as-is', () => {
  it('the documented two-operator wiring type-checks', () => {
    const minimal = { and, eq } satisfies IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']
    expect(typeof minimal.eq).toBe('function')
    expect(typeof minimal.and).toBe('function')
  })

  it('the full four-operator wiring type-checks', () => {
    // `isNull` and `or` gate `updateAssignmentScope` and the single-statement
    // `revokeRoleMany`; a caller who cannot pass them loses those paths.
    const full = { and, eq, isNull, or } satisfies IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']
    expect(typeof full.isNull).toBe('function')
    expect(typeof full.or).toBe('function')
  })

  it('the same bundle satisfies the mysql and sqlite configs', () => {
    // The operators do not vary by dialect, and the adapter branches on
    // `dialect` at runtime rather than on the operator types.
    const mysql = { and, eq, isNull, or } satisfies IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'mysql'>['ops']
    const sqlite = { and, eq, isNull, or } satisfies IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'sqlite'>['ops']
    expect(mysql.eq).toBe(sqlite.eq)
  })
})
