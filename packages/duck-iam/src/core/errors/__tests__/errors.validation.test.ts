import { describe, expect, it } from 'vitest'
import type { IamValidate } from '../../validate'
import { IamError, metaOf } from '../errors'
import { throwIamValidationFailed } from '../errors.validation'

const issue = (code: IamValidate.ValidationCode, message: string, path?: string): IamValidate.IIssue => ({
  type: 'error',
  code,
  message,
  path,
})

describe('throwIamValidationFailed', () => {
  it('throws IAM_VALIDATION_FAILED with the kind and formatted issues', () => {
    try {
      throwIamValidationFailed('rule', [issue('INVALID_EFFECT', 'no effect set', 'effect')])
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      const meta = metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED')
      expect(meta.kind).toBe('rule')
      expect(meta.issues).toEqual(['INVALID_EFFECT at "effect": no effect set'])
    }
  })

  it('formats an issue with no path without the "at" clause', () => {
    try {
      throwIamValidationFailed('policy', [issue('MISSING_FIELD', 'policy has no rules')])
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED')
      expect(meta.issues).toEqual(['MISSING_FIELD: policy has no rules'])
    }
  })

  it('drops warning-level issues, keeping only error-level ones', () => {
    try {
      throwIamValidationFailed('role', [
        issue('INVALID_TYPE', 'bad scope', 'scope'),
        { type: 'warning', code: 'UNKNOWN_FIELD', message: 'unused field' },
      ])
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED')
      expect(meta.issues).toHaveLength(1)
    }
  })

  it('accepts kind "rule", which the old IamValidationError union could not', () => {
    expect(() => throwIamValidationFailed('rule', [issue('INVALID_RULE', 'y')])).toThrow(IamError)
  })
})
