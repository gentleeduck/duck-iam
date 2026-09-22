import { and, eq, isNull, or } from 'drizzle-orm'
import { describe, expect, it } from 'vitest'
import type { IamDrizzle } from '../index'

// Type test: each `satisfies` is checked by tsc, so drizzle's own operators must wire into `ops` without a wrapper.
// INFO: parameters are contravariant, so an `unknown` parameter in `ops` would reject drizzle's real `eq`/`isNull`.
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
