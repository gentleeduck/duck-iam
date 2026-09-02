import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamLRUCache, iamLRUCache } from '../cache'

describe('IamLRUCache', () => {
  it('stores and retrieves values', () => {
    const cache = new IamLRUCache<string>(10, 60000)
    cache.set('key1', 'value1')
    expect(cache.get('key1')).toBe('value1')
  })

  it('returns undefined for missing keys', () => {
    const cache = new IamLRUCache<string>(10, 60000)
    expect(cache.get('missing')).toBeUndefined()
  })

  it('tracks size correctly', () => {
    const cache = new IamLRUCache<number>(10, 60000)
    expect(cache.size).toBe(0)
    cache.set('a', 1)
    cache.set('b', 2)
    expect(cache.size).toBe(2)
  })

  it('evicts oldest entry when at max size', () => {
    const cache = new IamLRUCache<string>(2, 60000)
    cache.set('a', '1')
    cache.set('b', '2')
    cache.set('c', '3') // should evict 'a'
    expect(cache.get('a')).toBeUndefined()
    expect(cache.get('b')).toBe('2')
    expect(cache.get('c')).toBe('3')
    expect(cache.size).toBe(2)
  })

  it('get() promotes entry to most recently used', () => {
    const cache = new IamLRUCache<string>(2, 60000)
    cache.set('a', '1')
    cache.set('b', '2')
    cache.get('a') // promote 'a'
    cache.set('c', '3') // should evict 'b' (least recently used)
    expect(cache.get('a')).toBe('1')
    expect(cache.get('b')).toBeUndefined()
    expect(cache.get('c')).toBe('3')
  })

  it('delete() removes an entry', () => {
    const cache = new IamLRUCache<string>(10, 60000)
    cache.set('a', '1')
    expect(cache.delete('a')).toBe(true)
    expect(cache.get('a')).toBeUndefined()
    expect(cache.size).toBe(0)
  })

  it('delete() returns false for missing key', () => {
    const cache = new IamLRUCache<string>(10, 60000)
    expect(cache.delete('missing')).toBe(false)
  })

  it('clear() removes all entries', () => {
    const cache = new IamLRUCache<string>(10, 60000)
    cache.set('a', '1')
    cache.set('b', '2')
    cache.clear()
    expect(cache.size).toBe(0)
    expect(cache.get('a')).toBeUndefined()
  })

  it('overwrites existing key without increasing size', () => {
    const cache = new IamLRUCache<string>(10, 60000)
    cache.set('a', '1')
    cache.set('a', '2')
    expect(cache.size).toBe(1)
    expect(cache.get('a')).toBe('2')
  })

  it('rejects negative maxSize', () => {
    expect(() => new IamLRUCache<string>(0, 1000)).toThrow(RangeError)
    expect(() => new IamLRUCache<string>(-1, 1000)).toThrow(RangeError)
  })

  it('rejects negative ttlMs', () => {
    expect(() => new IamLRUCache<string>(10, -1)).toThrow(RangeError)
  })

  it('rejects non-finite maxSize and ttlMs', () => {
    expect(() => new IamLRUCache<string>(Number.NaN, 1000)).toThrow(RangeError)
    expect(() => new IamLRUCache<string>(Number.POSITIVE_INFINITY, 1000)).toThrow(RangeError)
    expect(() => new IamLRUCache<string>(10, Number.NaN)).toThrow(RangeError)
    expect(() => new IamLRUCache<string>(10, Number.POSITIVE_INFINITY)).toThrow(RangeError)
  })

  it('holds a single entry at maxSize 1', () => {
    const cache = new IamLRUCache<string>(1, 60000)
    cache.set('a', '1')
    cache.set('b', '2')
    expect(cache.size).toBe(1)
    expect(cache.get('a')).toBeUndefined()
    expect(cache.get('b')).toBe('2')
  })

  it('allows ttlMs of 0 without throwing', () => {
    expect(() => new IamLRUCache<string>(10, 0)).not.toThrow()
  })

  it('evicts in correct LRU order with more than 2 entries', () => {
    const cache = new IamLRUCache<string>(3, 60000)
    cache.set('a', '1')
    cache.set('b', '2')
    cache.set('c', '3')
    cache.get('a') // promote 'a'
    cache.set('d', '4') // should evict 'b' (least recently used)
    expect(cache.get('b')).toBeUndefined()
    expect(cache.get('a')).toBe('1')
    expect(cache.get('c')).toBe('3')
    expect(cache.get('d')).toBe('4')
  })

  describe('TTL expiration', () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('returns undefined for expired entries', () => {
      const cache = new IamLRUCache<string>(10, 100) // 100ms TTL
      cache.set('a', '1')
      expect(cache.get('a')).toBe('1')

      vi.advanceTimersByTime(150)
      expect(cache.get('a')).toBeUndefined()
    })

    it('removes expired entries on get', () => {
      const cache = new IamLRUCache<string>(10, 100)
      cache.set('a', '1')
      vi.advanceTimersByTime(150)
      cache.get('a') // triggers cleanup
      expect(cache.get('a')).toBeUndefined()
    })
  })

  describe('stats', () => {
    it('counts hits and misses', () => {
      const cache = new IamLRUCache<string>(10, 60000)
      cache.set('a', '1')
      cache.get('a') // hit
      cache.get('a') // hit
      cache.get('missing') // miss
      expect(cache.stats).toEqual({ hits: 2, misses: 1, size: 1 })
    })

    it('counts expired reads as misses', () => {
      vi.useFakeTimers()
      try {
        const cache = new IamLRUCache<string>(10, 100)
        cache.set('a', '1')
        vi.advanceTimersByTime(150)
        cache.get('a') // expired -> miss
        expect(cache.stats.misses).toBe(1)
        expect(cache.stats.hits).toBe(0)
      } finally {
        vi.useRealTimers()
      }
    })

    it('resetStats zeroes counters', () => {
      const cache = new IamLRUCache<string>(10, 60000)
      cache.set('a', '1')
      cache.get('a')
      cache.get('missing')
      cache.resetStats()
      expect(cache.stats).toEqual({ hits: 0, misses: 0, size: 1 })
    })
  })

  describe('entries()', () => {
    it('yields nothing for an empty cache', () => {
      const cache = new IamLRUCache<string>(10, 60000)
      expect([...cache.entries()]).toEqual([])
    })

    it('yields live entries in insertion order', () => {
      const cache = new IamLRUCache<string>(10, 60000)
      cache.set('a', '1')
      cache.set('b', '2')
      expect([...cache.entries()]).toEqual([
        ['a', '1'],
        ['b', '2'],
      ])
    })

    it('does not count as a read: stats and LRU order are untouched', () => {
      const cache = new IamLRUCache<string>(2, 60000)
      cache.set('a', '1')
      cache.set('b', '2')
      expect([...cache.entries()]).toHaveLength(2)
      expect(cache.stats).toEqual({ hits: 0, misses: 0, size: 2 })
      cache.set('c', '3')
      expect(cache.get('a')).toBeUndefined()
    })

    it('skips expired entries', () => {
      vi.useFakeTimers()
      try {
        const cache = new IamLRUCache<string>(10, 100)
        cache.set('a', '1')
        vi.advanceTimersByTime(150)
        cache.set('b', '2')
        expect([...cache.entries()]).toEqual([['b', '2']])
      } finally {
        vi.useRealTimers()
      }
    })
  })
})

describe('iamLRUCache()', () => {
  it('builds an IamLRUCache with the same constructor arguments', () => {
    const cache = iamLRUCache<string>(2, 60000)
    expect(cache).toBeInstanceOf(IamLRUCache)
    cache.set('a', '1')
    cache.set('b', '2')
    cache.set('c', '3')
    expect(cache.size).toBe(2)
    expect(cache.get('a')).toBeUndefined()
  })

  it('propagates constructor validation', () => {
    expect(() => iamLRUCache<string>(0, 1000)).toThrow(RangeError)
    expect(() => iamLRUCache<string>(10, -1)).toThrow(RangeError)
  })
})
