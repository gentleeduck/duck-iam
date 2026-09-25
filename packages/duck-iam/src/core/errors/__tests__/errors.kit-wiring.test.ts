import { describe, expect, it } from 'vitest'
import { IamError, metaOf } from '../errors'

// Compiles only if `IamError` is usable as both a value (the class) and a type parameterized by a code —
// exactly the shape every existing call site in this package already relies on (see plan Review Focus #2).
function onlyRoleNotFound(err: IamError<'IAM_ROLE_NOT_FOUND'>): string {
  return metaOf(err, 'IAM_ROLE_NOT_FOUND').adapter
}

describe('IamError is both the class and a code-parameterized type', () => {
  it('constructs, narrows via instanceof, and narrows further via a literal code check', () => {
    const err: unknown = new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'drizzle' })
    expect(err).toBeInstanceOf(IamError)
    if (err instanceof IamError && err.code === 'IAM_ROLE_NOT_FOUND') {
      expect(onlyRoleNotFound(err)).toBe('drizzle')
    } else {
      expect.unreachable()
    }
  })
})
