import { describe, expect, it } from 'vitest'
import { defineRole } from '../role'

// `inherits()` replaces rather than appends, unlike `grant*`; a dropped parent shows up as a denial, not an error.
describe('RoleBuilder.inherits replaces', () => {
  it('keeps only the last call', () => {
    expect(defineRole('r').inherits('a').inherits('b').build().inherits).toEqual(['b'])
  })

  // `build()` omits an empty list, so the wipe looks like a role that never declared a parent.
  it('wipes the list when called with no arguments', () => {
    expect(defineRole('r').inherits('a', 'b').inherits().build().inherits).toBeUndefined()
    expect(defineRole('r').build().inherits).toBeUndefined()
  })

  it('accumulates within a single call, which is the only way to declare two parents', () => {
    expect(defineRole('r').inherits('a', 'b').build().inherits).toEqual(['a', 'b'])
  })

  // Control: `grant` accumulates, so "replaces" is specific to `inherits`.
  it('control: grant accumulates across calls', () => {
    expect(defineRole('r').grant('read', 'post').grant('write', 'post').build().permissions).toHaveLength(2)
  })
})
