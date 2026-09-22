import { describe, expect, it } from 'vitest'
import { iamAssertRoleExists, iamIsForeignKeyViolation, iamUnknownRoleError } from '../assignment-target'

// No MySQL or SQLite suite exists, so these real driver strings are the only coverage for those dialects.
describe('iamIsForeignKeyViolation recognises every dialect its docblock claims', () => {
  it('Postgres: "violates foreign key constraint"', () => {
    expect(
      iamIsForeignKeyViolation(
        new Error(
          'insert or update on table "iam_assignments" violates foreign key constraint "fk_iam_assignments_role"',
        ),
      ),
    ).toBe(true)
  })

  it('MySQL: "a foreign key constraint fails"', () => {
    expect(
      iamIsForeignKeyViolation(
        new Error('Cannot add or update a child row: a foreign key constraint fails (`iam`.`iam_assignments`)'),
      ),
    ).toBe(true)
  })

  it('SQLite: "FOREIGN KEY constraint failed"', () => {
    expect(iamIsForeignKeyViolation(new Error('FOREIGN KEY constraint failed'))).toBe(true)
  })

  it('Postgres SQLSTATE 23503 counts even when the text does not match', () => {
    // `lc_messages` can translate the message, so the SQLSTATE must match on its own.
    const localised = Object.assign(new Error('Einfügen oder Aktualisieren verletzt Fremdschlüssel'), {
      code: '23503',
    })
    expect(iamIsForeignKeyViolation(localised)).toBe(true)
  })

  it('walks the cause chain, which is where drizzle puts the real error', () => {
    // Drizzle reports `Failed query: <sql>` and hangs the violation off `.cause`.
    const wrapped = new Error('Failed query: insert into "iam_assignments" ...', {
      cause: new Error('insert or update on table "iam_assignments" violates foreign key constraint'),
    })
    expect(wrapped.message).not.toMatch(/foreign key constraint/i)
    expect(iamIsForeignKeyViolation(wrapped)).toBe(true)
  })

  it('finds a SQLSTATE nested two levels down', () => {
    const nested = new Error('outer', {
      cause: new Error('middle', { cause: Object.assign(new Error('x'), { code: '23503' }) }),
    })
    expect(iamIsForeignKeyViolation(nested)).toBe(true)
  })

  it('is false for an unrelated driver error', () => {
    expect(iamIsForeignKeyViolation(new Error('duplicate key value violates unique constraint'))).toBe(false)
    expect(iamIsForeignKeyViolation(Object.assign(new Error('nope'), { code: '23505' }))).toBe(false)
  })

  it('is false for non-errors rather than throwing', () => {
    for (const value of [null, undefined, 'foreign key constraint', 42, { message: 12345 }]) {
      expect(iamIsForeignKeyViolation(value)).toBe(false)
    }
  })

  it('terminates on a cyclic cause chain', () => {
    const a = new Error('a')
    Object.defineProperty(a, 'cause', { value: a })
    expect(iamIsForeignKeyViolation(a)).toBe(false)
  })
})

describe('the unknown-role refusal is worded identically on every adapter', () => {
  const EXPECTED = 'cannot assign a role that is not stored; save the role before granting it'

  it('carries the shared wording and the adapter name', () => {
    // The conformance suite only asserts `rejects.toThrow()`, so the wording is pinned here.
    expect(iamUnknownRoleError('drizzle').message).toBe(`[@gentleduck/iam:drizzle] ${EXPECTED}`)
    expect(iamUnknownRoleError('memory').message).toBe(`[@gentleduck/iam:memory] ${EXPECTED}`)
  })

  it('keeps the driver error as the cause when there is one', () => {
    const driver = new Error('violates foreign key constraint')
    expect(iamUnknownRoleError('drizzle', driver).cause).toBe(driver)
    expect(iamUnknownRoleError('drizzle').cause).toBeUndefined()
  })

  it('iamAssertRoleExists throws that same error and only when absent', () => {
    expect(() => iamAssertRoleExists('memory', true)).not.toThrow()
    expect(() => iamAssertRoleExists('memory', false)).toThrow(EXPECTED)
  })
})
