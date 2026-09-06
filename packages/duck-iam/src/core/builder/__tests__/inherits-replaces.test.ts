import { describe, expect, it } from 'vitest'
import { defineRole } from '../role'

/**
 * `inherits()` assigns rather than appends. That is deliberate and pinned in
 * `builder.test.ts`, but it reads like every neighbouring `grant*`, all of
 * which accumulate - and the zero-argument call, which silently wipes a
 * previously declared parent list, was neither documented nor pinned. Dropping
 * an inheritance edge drops every permission that flowed through it, so the
 * symptom is a denial rather than an error.
 */
describe('RoleBuilder.inherits replaces', () => {
  it('keeps only the last call', () => {
    expect(defineRole('r').inherits('a').inherits('b').build().inherits).toEqual(['b'])
  })

  // `build()` omits an empty list rather than emitting `[]`, so the wipe is
  // indistinguishable from a role that never declared a parent.
  it('wipes the list when called with no arguments', () => {
    expect(defineRole('r').inherits('a', 'b').inherits().build().inherits).toBeUndefined()
    expect(defineRole('r').build().inherits).toBeUndefined()
  })

  it('accumulates within a single call, which is the only way to declare two parents', () => {
    expect(defineRole('r').inherits('a', 'b').build().inherits).toEqual(['a', 'b'])
  })

  // Control: the sibling that does accumulate, so "replaces" is a property of
  // this method and not of the builder.
  it('control: grant accumulates across calls', () => {
    expect(defineRole('r').grant('read', 'post').grant('write', 'post').build().permissions).toHaveLength(2)
  })
})
