import { describe, expect, it } from 'vitest'
import { appliedRows, creditWrites } from '../index'

/** A stand-in for the shape the drizzle adapter matches on. */
type Row = { id: string; scope?: string }
const accountsFor = (r: Row, w: Row): boolean => r.id === w.id && (r.scope === undefined || r.scope === w.scope)

describe('creditWrites', () => {
  it('credits each requested row that accounts for a write', () => {
    expect(creditWrites([{ id: 'a' }, { id: 'b' }], [{ id: 'b' }], accountsFor)).toEqual([1])
  })

  it('credits a write once when two rows ask for the same thing', () => {
    expect(creditWrites([{ id: 'a' }, { id: 'a' }], [{ id: 'a' }], accountsFor)).toEqual([0])
  })

  it('credits the first row when an earlier one already covers a later one', () => {
    const requested: Row[] = [{ id: 'a' }, { id: 'a', scope: 'org-1' }]
    const written: Row[] = [{ id: 'a', scope: 'org-1' }]

    // The unscoped row covers every scope, so it claims the write first.
    expect(creditWrites(requested, written, accountsFor)).toEqual([0])
  })

  it('never credits more rows than there were writes', () => {
    const requested: Row[] = [{ id: 'a' }, { id: 'a' }, { id: 'a' }]
    const credited = creditWrites(requested, [{ id: 'a' }, { id: 'a' }], accountsFor)

    // Two writes, three identical requests: the third has nothing left to claim.
    expect(credited).toEqual([0, 1])
  })

  it('credits a wildcard row once, however many writes it matches', () => {
    expect(
      creditWrites(
        [{ id: 'a' }],
        [
          { id: 'a', scope: 'x' },
          { id: 'a', scope: 'y' },
        ],
        accountsFor,
      ),
    ).toEqual([0])
  })

  it('credits nothing when nothing was written', () => {
    expect(creditWrites([{ id: 'a' }], [], accountsFor)).toEqual([])
  })
})

describe('appliedRows', () => {
  it('marks every row applied and carries the row itself', () => {
    const rows = [{ id: 'a' }, { id: 'b' }]
    const result = appliedRows(rows, [0])

    expect(result).toEqual({
      applied: 2,
      outcomes: [
        { ok: true, row: { id: 'a' }, value: { changed: true } },
        { ok: true, row: { id: 'b' }, value: { changed: false } },
      ],
    })
    // The same objects passed in, so callers can compare by identity.
    expect(result.outcomes[0]?.row).toBe(rows[0])
  })

  it('leaves changed off entirely when the adapter could not say', () => {
    const result = appliedRows([{ id: 'a' }], null)
    const first = result.outcomes[0]

    expect(first).toEqual({ ok: true, row: { id: 'a' }, value: {} })
    expect(first?.ok === true && 'changed' in first.value).toBe(false)
  })

  it('keeps two structurally identical rows as two addressable outcomes', () => {
    // Only the first is credited with the single write.
    const result = appliedRows([{ id: 'a' }, { id: 'a' }], [0])

    expect(result.outcomes).toHaveLength(2)
    expect(result.outcomes.map((o) => (o.ok ? o.value.changed : null))).toEqual([true, false])
  })
})
