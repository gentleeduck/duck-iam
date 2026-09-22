import { describe, expect, it } from 'vitest'
import { isSoftDeleted } from '../identities'

describe('isSoftDeleted', () => {
  it('is false when deletedAt is null or absent', () => {
    expect(isSoftDeleted({ deletedAt: null })).toBe(false)
    expect(isSoftDeleted({})).toBe(false)
  })

  it('is true when deletedAt is set', () => {
    expect(isSoftDeleted({ deletedAt: new Date() })).toBe(true)
  })

  it('is true for a deletedAt in the future, which is how the grace period is stored', () => {
    // `softDelete(id, gracePeriodMs)` writes now + grace, so a future value is the
    // normal case and must still hide the row.
    expect(isSoftDeleted({ deletedAt: new Date(Date.now() + 60_000) })).toBe(true)
  })

  it('accepts a numeric timestamp as well as a Date', () => {
    expect(isSoftDeleted({ deletedAt: Date.now() })).toBe(true)
  })
})
