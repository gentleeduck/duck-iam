import { describe, expect, it } from 'vitest'
import * as Core from '../core'
import { IamRegexInputTooLargeError } from '../core/conditions'
import * as Iam from '../index'

/**
 * `IamRegexInputTooLargeError` is the package's only custom error class, built
 * for `instanceof` discrimination and carrying a stable `tag`, and it was in no
 * barrel - so the only handle a consumer had was a string comparison against
 * `err.name`. Five tuning constants from the same file were exported.
 */
describe('the custom error class is reachable', () => {
  it('is exported from the core barrel', () => {
    expect(Object.hasOwn(Core, 'IamRegexInputTooLargeError')).toBe(true)
  })

  it('is exported from the package root', () => {
    expect(Object.hasOwn(Iam, 'IamRegexInputTooLargeError')).toBe(true)
  })

  it('is a constructible Error subclass', () => {
    const err = new IamRegexInputTooLargeError('subject.id', 10_000)
    expect(err).toBeInstanceOf(Error)
    expect(err.field).toBe('subject.id')
    expect(err.length).toBe(10_000)
  })

  it('keeps its stable tag', () => {
    expect(new IamRegexInputTooLargeError('f', 1).tag).toBe('duck-iam/regex-input-too-large')
  })

  it('is the class the evaluator actually throws', async () => {
    const { evalMatchesOp, MAX_REGEX_INPUT_LENGTH } = await import('../core/conditions/conditions.libs')
    expect(() => evalMatchesOp('a'.repeat(MAX_REGEX_INPUT_LENGTH + 1), '^a')).toThrow(IamRegexInputTooLargeError)
  })
})

/**
 * `Batch` and `Pending` appear inside root-exported signatures
 * (`admin.assignRoles`, `bound.pending`) but no barrel named them, so a
 * consumer wanting to annotate a variable had to reach for `ReturnType<>` or
 * `any`. Type-only, so this is a compile-time assertion.
 */
describe('types used in public signatures are nameable', () => {
  it('Batch.Result can annotate an assignRoles result', () => {
    const result: Core.Batch.Result<{ subjectId: string }, Core.Batch.Change> = {
      applied: 1,
      outcomes: [{ ok: true, row: { subjectId: 'u1' }, value: { changed: true } }],
    }
    expect(result.applied).toBe(1)
  })

  it('Pending.Invalidation can annotate a buffered entry', () => {
    const entry: Core.Pending.Invalidation = { kind: 'subject', subjectId: 'u1' }
    expect(entry.kind).toBe('subject')
  })
})
