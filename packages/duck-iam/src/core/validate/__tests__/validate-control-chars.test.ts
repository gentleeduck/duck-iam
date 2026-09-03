import { describe, expect, it } from 'vitest'
import { validatePolicy } from '../validate'

const NUL = String.fromCharCode(0)

function policyWith(actions: string[], resources: string[]): unknown {
  return {
    algorithm: 'deny-overrides',
    id: 'p1',
    name: 'p1',
    rules: [{ actions, conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources }],
  }
}

function actionIssues(result: ReturnType<typeof validatePolicy>): string[] {
  return result.issues.filter((i) => (i.path ?? '').startsWith('rules[0].actions')).map((i) => i.message)
}

function resourceIssues(result: ReturnType<typeof validatePolicy>): string[] {
  return result.issues.filter((i) => (i.path ?? '').startsWith('rules[0].resources')).map((i) => i.message)
}

/**
 * A control character is invisible in every UI that would display a rule, so a
 * name carrying one reads as a different name than it is - the reviewer sees
 * `read`, the engine matches something else. Rejected at import rather than
 * normalized: silently rewriting a name would change which requests the rule
 * matches.
 */
describe('validatePolicy rejects control characters in action and resource names', () => {
  it('rejects a NUL in an action', () => {
    const result = validatePolicy(policyWith([`read${NUL}post`], ['post']))
    expect(result.valid).toBe(false)
    expect(actionIssues(result)).toContain('Action must not contain control characters')
  })

  it('rejects a NUL in a resource', () => {
    const result = validatePolicy(policyWith(['read'], [`post${NUL}x`]))
    expect(result.valid).toBe(false)
    expect(resourceIssues(result)).toContain('Resource must not contain control characters')
  })

  it.each([
    ['newline', '\n'],
    ['carriage return', '\r'],
    ['tab', '\t'],
    ['escape', String.fromCharCode(27)],
    ['delete', String.fromCharCode(127)],
  ])('rejects a %s in an action', (_label, ch) => {
    expect(validatePolicy(policyWith([`read${ch}`], ['post'])).valid).toBe(false)
  })

  it('reports the offending index', () => {
    const result = validatePolicy(policyWith(['read', `write${NUL}`], ['post']))
    expect(result.issues.some((i) => i.path === 'rules[0].actions[1]')).toBe(true)
    expect(result.issues.some((i) => i.path === 'rules[0].actions[0]')).toBe(false)
  })

  // Controls: the check must not reject the names real policies use, or every
  // assertion above would pass on a validator that rejects everything.
  it.each([['read'], ['*'], ['post.comment'], ['org:member'], ['@scope'], ['résumé'], ['読む']])(
    'still accepts %j',
    (name) => {
      expect(validatePolicy(policyWith([name], [name])).valid).toBe(true)
    },
  )
})
