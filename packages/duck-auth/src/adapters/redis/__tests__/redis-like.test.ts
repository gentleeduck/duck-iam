import { describe, expect, it } from 'vitest'
import { FakeRedis } from '../redis-like'

describe('FakeRedis.scan - glob MATCH', () => {
  async function withKeys(keys: string[]): Promise<FakeRedis> {
    const r = new FakeRedis()
    for (const k of keys) await r.set(k, '1')
    return r
  }

  it('matches plain prefix glob', async () => {
    const r = await withKeys(['user:1', 'user:2', 'session:1'])
    const [, matched] = await r.scan('0', { match: 'user:*' })
    expect(matched.sort()).toEqual(['user:1', 'user:2'])
  })

  it('matches plain suffix glob', async () => {
    const r = await withKeys(['a-x', 'b-x', 'b-y'])
    const [, matched] = await r.scan('0', { match: '*-x' })
    expect(matched.sort()).toEqual(['a-x', 'b-x'])
  })

  it('matches inner star glob', async () => {
    const r = await withKeys(['a-1-z', 'a-22-z', 'a-z'])
    const [, matched] = await r.scan('0', { match: 'a-*-z' })
    expect(matched.sort()).toEqual(['a-1-z', 'a-22-z'])
  })

  it('multiple stars collapse cleanly (a***b == a*b)', async () => {
    const r = await withKeys(['ab', 'aXb', 'aXYZb', 'aXc'])
    const [, matched] = await r.scan('0', { match: 'a***b' })
    expect(matched.sort()).toEqual(['aXYZb', 'aXb', 'ab'])
  })

  it('exact pattern matches only the exact key', async () => {
    const r = await withKeys(['exact', 'exacto'])
    const [, matched] = await r.scan('0', { match: 'exact' })
    expect(matched).toEqual(['exact'])
  })

  it('a pathological multi-star non-matching pattern stays linear (ReDoS defense)', async () => {
    // Pattern like `a*a*a*a*a*X` matched against `aaaaaaaaaa...Y` would
    // have driven the legacy regex into super-linear backtracking. With
    // the iterative matcher this returns false in O(n*m).
    const r = await withKeys(['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaY'])
    const start = performance.now()
    const [, matched] = await r.scan('0', { match: 'a*a*a*a*a*a*a*a*X' })
    const elapsed = performance.now() - start
    expect(matched).toEqual([])
    // Loose bound: should complete well under 100ms on any modern
    // machine. Catastrophic backtracking would push it into seconds.
    expect(elapsed).toBeLessThan(100)
  })

  it('a pattern containing `?` matches `?` literally (legacy threw SyntaxError, crashing scan)', async () => {
    const r = await withKeys(['key?1', 'key:1'])
    const [, matched] = await r.scan('0', { match: 'key?1' })
    // The legacy code: regex `^key?1$` is invalid syntax in some engines
    // because `?` after a non-quantifiable char threw. The iterative
    // matcher treats `?` as a literal char so `key?1` matches.
    expect(matched).toEqual(['key?1'])
  })

  it('a pattern containing `[` does not crash (legacy regex `^[$` was invalid)', async () => {
    const r = await withKeys(['[abc]'])
    const [, matched] = await r.scan('0', { match: '[abc]' })
    expect(matched).toEqual(['[abc]'])
  })

  it('an oversize pattern is rejected (length cap defends against an attacker-supplied huge pattern)', async () => {
    const r = await withKeys(['k'])
    const huge = `${'*'.repeat(257)}k`
    const [, matched] = await r.scan('0', { match: huge })
    expect(matched).toEqual([])
  })
})
