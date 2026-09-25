import type { IamValidate } from '../validate'
import { throwIamError } from './errors'

/**
 * Throws `IAM_VALIDATION_FAILED` for every error-level issue in `issues`. The one path every validator-rejection
 * site shares: `engine.libs.ts`'s write-time guard and the three builder `.build()` methods used to each format
 * their own message and throw a plain `Error`; this is what they now call instead.
 */
export function throwIamValidationFailed(
  kind: 'policy' | 'role' | 'rule' | 'request',
  issues: readonly IamValidate.IIssue[],
): never {
  const errors = issues.filter((issue) => issue.type === 'error')
  const formatted = errors.map((issue) => {
    const where = issue.path ? ` at "${issue.path}"` : ''
    // An empty message (a caller redacting it before handing issues here) omits the trailing ": " too.
    return issue.message ? `${issue.code}${where}: ${issue.message}` : `${issue.code}${where}`
  })
  throwIamError('IAM_VALIDATION_FAILED', { kind, issues: formatted })
}
