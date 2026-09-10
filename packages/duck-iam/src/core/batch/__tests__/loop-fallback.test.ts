import { describe, expect, it, vi } from 'vitest'
import { loopFallback } from '../batch'

// Backs every adapter with no set-based write form; a throw must abort, not become a per-row failure.
describe('loopFallback', () => {
  it('runs once per row, in order', async () => {
    const seen: string[] = []
    const result = await loopFallback(['a', 'b', 'c'], async (row) => {
      seen.push(row)
      return row.toUpperCase()
    })
    expect(seen).toEqual(['a', 'b', 'c'])
    expect(result.outcomes.map((o) => o.ok && o.value)).toEqual(['A', 'B', 'C'])
  })

  it('reports every row as applied', async () => {
    const result = await loopFallback([1, 2], async (n) => n * 2)
    expect(result.applied).toBe(2)
    expect(result.outcomes.every((o) => o.ok)).toBe(true)
  })

  it('carries the row itself on each outcome', async () => {
    const result = await loopFallback(['x'], async () => undefined)
    expect(result.outcomes[0]?.row).toBe('x')
  })

  it('rejects on the first throw rather than reporting a soft failure', async () => {
    const run = vi.fn(async (row: string) => {
      if (row === 'b') throw new Error('write failed')
      return row
    })
    await expect(loopFallback(['a', 'b', 'c'], run)).rejects.toThrow('write failed')
    // `c` is never attempted.
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('is a no-op on an empty row list', async () => {
    const run = vi.fn(async (n: number) => n)
    const result = await loopFallback([], run)
    expect(run).not.toHaveBeenCalled()
    expect(result).toEqual({ applied: 0, outcomes: [] })
  })

  it('awaits serially, never concurrently', async () => {
    let inFlight = 0
    let maxInFlight = 0
    await loopFallback([1, 2, 3], async () => {
      inFlight++
      maxInFlight = Math.max(maxInFlight, inFlight)
      await Promise.resolve()
      inFlight--
    })
    expect(maxInFlight).toBe(1)
  })
})
