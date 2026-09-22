/**
 * `validateRoles` takes untrusted roles (adapter rows, config, form bodies): malformed entries come back as
 * `INVALID_TYPE` issues, never a `TypeError`, and a string `inherits` is not walked per character.
 */
import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { validateRoles } from '../validate'

/** Malformed inputs, cast at the boundary the function guards. */
const MALFORMED: readonly (readonly [string, unknown])[] = [
  ['null', null],
  ['undefined', undefined],
  ['a string', 'admin'],
  ['a number', 42],
  ['an array', []],
  ['no id', { permissions: [] }],
  ['a non-string id', { id: 7, permissions: [] }],
  ['an empty id', { id: '', permissions: [] }],
  ['no permissions', { id: 'r1' }],
  ['a non-array permissions', { id: 'r1', permissions: 'all' }],
  ['a string inherits', { id: 'r1', inherits: 'admin', permissions: [] }],
]

const GOOD: AccessControl.IRole = { id: 'reader', inherits: [], name: 'Reader', permissions: [] }

describe('validateRoles on input it does not trust', () => {
  it('CONTROL: a well-formed role validates, so the assertions below are about the malformed ones', () => {
    const result = validateRoles([GOOD])
    expect({ errors: result.issues.filter((i) => i.type === 'error'), valid: result.valid }).toEqual({
      errors: [],
      valid: true,
    })
  })

  for (const [label, role] of MALFORMED) {
    it(`reports ${label} as an issue instead of throwing`, () => {
      // The cast is the point: this is the untrusted value the signature exists to accept.
      const roles = [role] as unknown as readonly AccessControl.IRole[]
      const result = validateRoles(roles)
      expect({
        code: result.issues[0]?.code,
        errorCount: result.issues.filter((i) => i.type === 'error').length,
        valid: result.valid,
      }).toEqual({ code: 'INVALID_TYPE', errorCount: 1, valid: false })
    })
  }

  it('a malformed entry does not stop the good roles beside it from being checked', () => {
    const roles = [
      null,
      GOOD,
      { id: 'reader', inherits: [], name: 'Dup', permissions: [] },
    ] as unknown as readonly AccessControl.IRole[]
    const result = validateRoles(roles)

    // Both errors: the malformed row is skipped, not allowed to hide the rows after it.
    expect(
      result.issues
        .filter((i) => i.type === 'error')
        .map((i) => i.code)
        .sort(),
    ).toEqual(['DUPLICATE_ROLE_ID', 'INVALID_TYPE'])
  })

  it('a string inherits is not walked character by character', () => {
    const roles = [{ id: 'r1', inherits: 'admin', permissions: [] }] as unknown as readonly AccessControl.IRole[]
    const result = validateRoles(roles)

    // Guards against five DANGLING_INHERIT issues for 'a','d','m','i','n'.
    expect(result.issues.filter((i) => i.code === 'DANGLING_INHERIT')).toEqual([])
  })
})
