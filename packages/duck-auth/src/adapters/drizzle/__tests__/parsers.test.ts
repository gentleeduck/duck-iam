import { describe, expect, it } from 'vitest'
import { parseProviderLinks } from '../_parsers'

describe('parseProviderLinks', () => {
  describe('returns [] on malformed JSON', () => {
    it.each<[string]>([
      ['null'],
      ['true'],
      ['42'],
      ['"oops"'],
      ['{}'],
      ['{"some":"object"}'],
      ['not-json-at-all'],
      ['{"truncated":'],
      [''],
    ])('rejects %p -> []', (raw) => {
      expect(parseProviderLinks(raw)).toEqual([])
    })

    it.each<[unknown]>([[null], [undefined]])('rejects %p (non-string input) -> []', (raw) => {
      expect(parseProviderLinks(raw as never)).toEqual([])
    })
  })

  describe('passes well-formed arrays through', () => {
    it('full link with providerSub + addedAt', () => {
      const raw = JSON.stringify([{ providerId: 'google', providerSub: 'sub-1', addedAt: 1234 }])
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'google', providerSub: 'sub-1', addedAt: 1234 }])
    })

    it('link without providerSub (optional field)', () => {
      const raw = JSON.stringify([{ providerId: 'magic-link', addedAt: 5678 }])
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'magic-link', addedAt: 5678 }])
    })

    it('multiple links', () => {
      const raw = JSON.stringify([
        { providerId: 'google', providerSub: 'sub-1', addedAt: 1 },
        { providerId: 'github', providerSub: 'sub-2', addedAt: 2 },
      ])
      expect(parseProviderLinks(raw)).toHaveLength(2)
    })
  })

  describe('filters individual malformed entries', () => {
    it('drops entry missing providerId; keeps the rest', () => {
      const raw = JSON.stringify([
        { providerId: 'google', addedAt: 1 },
        { addedAt: 2 }, // missing providerId
        { providerId: 'github', addedAt: 3 },
      ])
      const result = parseProviderLinks(raw)
      expect(result).toHaveLength(2)
      expect(result.map((p) => p.providerId)).toEqual(['google', 'github'])
    })

    it('drops entry with non-string providerId', () => {
      const raw = JSON.stringify([
        { providerId: 'google', addedAt: 1 },
        { providerId: 42, addedAt: 2 }, // number
      ])
      const result = parseProviderLinks(raw)
      expect(result).toHaveLength(1)
      expect(result[0]!.providerId).toBe('google')
    })

    it('drops entry with empty-string providerId', () => {
      const raw = JSON.stringify([
        { providerId: '', addedAt: 1 },
        { providerId: 'github', addedAt: 2 },
      ])
      expect(parseProviderLinks(raw)).toHaveLength(1)
    })

    it('drops entry with non-string providerSub', () => {
      const raw = JSON.stringify([{ providerId: 'google', providerSub: 42, addedAt: 1 }])
      expect(parseProviderLinks(raw)).toEqual([])
    })

    it('drops entry with non-finite addedAt (NaN, Infinity, string)', () => {
      const goodArr = [{ providerId: 'google', addedAt: 1 }]
      const goodRaw = JSON.stringify(goodArr)
      expect(parseProviderLinks(goodRaw)).toEqual(goodArr)
      // NaN / Infinity round-trip to `null` via JSON.stringify, so we
      // must inject them via raw strings.
      expect(parseProviderLinks('[{"providerId":"google","addedAt":NaN}]')).toEqual([])
      expect(parseProviderLinks('[{"providerId":"google","addedAt":"yesterday"}]')).toEqual([])
    })

    it('defaults missing addedAt to 0 (legacy-row tolerance)', () => {
      const raw = JSON.stringify([{ providerId: 'legacy' }])
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'legacy', addedAt: 0 }])
    })

    it('accepts addedAt === 0 (epoch start - corner case)', () => {
      const raw = JSON.stringify([{ providerId: 'epoch', addedAt: 0 }])
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'epoch', addedAt: 0 }])
    })

    it('drops `null` entries inside the array', () => {
      const raw = '[null, {"providerId":"good","addedAt":1}, null]'
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'good', addedAt: 1 }])
    })

    it('drops primitives (number, string, boolean) inside the array', () => {
      const raw = '[42, "oops", true, {"providerId":"good","addedAt":1}]'
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'good', addedAt: 1 }])
    })

    it('drops nested-array entries', () => {
      const raw = JSON.stringify([['nested'], { providerId: 'good', addedAt: 1 }])
      expect(parseProviderLinks(raw)).toEqual([{ providerId: 'good', addedAt: 1 }])
    })
  })
})
