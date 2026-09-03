import { describe, expect, it } from 'vitest'
import * as Iam from '../index'

/**
 * The package root must not hand out anything a consumer can mutate to change
 * an authorization decision. Each name below is a live shared object behind an
 * innocuous type: reassigning one member is enough to retire every deny rule
 * that depends on it, in both evaluation modes, with no error and no log.
 *
 * This is a surface test, not a behaviour test - it fails the moment a barrel
 * starts re-exporting one again, which is how the first two escaped.
 */
const MUTABLE_INTERNALS = [
  // The operator table. `ops.eq = () => false` retires every `eq` deny rule.
  'ops',
  // Typed `ReadonlySet`, erases to a live `Set`. Deleting a root makes every
  // path under it unresolvable, and `pathCache` memoizes the result.
  'ALLOWED_ROOTS',
  // The process-wide compile pool: seat a permissive RegExp under a pattern a
  // deny rule relies on and it is used from then on.
  'regexCache',
  // The dot-path segment pool: seat a bogus segment list under a resolved path.
  'pathCache',
  // Rule-combining table; replacing an algorithm rewrites every verdict.
  'combiners',
] as const

describe('public surface: mutable internals stay internal', () => {
  for (const name of MUTABLE_INTERNALS) {
    it(`does not export \`${name}\` from the package root`, () => {
      expect(Object.hasOwn(Iam, name)).toBe(false)
    })
  }

  it('exports the sanctioned cache-clearing helpers instead', () => {
    expect(typeof Iam.iamClearRegexCache).toBe('function')
    expect(typeof Iam.clearPathCache).toBe('function')
  })

  // Positive control: without this, every assertion above would also pass if
  // `Object.hasOwn` simply did not see module-namespace members, and the suite
  // would report green while pinning nothing.
  it('detects a name that IS exported, so the assertions above can fail', () => {
    expect(Object.hasOwn(Iam, 'iamClearRegexCache')).toBe(true)
    expect(Object.hasOwn(Iam, 'clearPathCache')).toBe(true)
  })
})
