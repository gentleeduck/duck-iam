import { describe, expect, it } from 'vitest'
import { authParseProviderLinks } from '../_parsers'

describe('authParseProviderLinks', () => {
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
      expect(authParseProviderLinks(raw)).toEqual([])
    })

    it.each<[unknown]>([[null], [undefined]])('rejects %p (non-string input) -> []', (raw) => {
      expect(authParseProviderLinks(raw as never)).toEqual([])
    })
  })

  describe('passes well-formed arrays through', () => {
    it('full link with providerSub + addedAt', () => {
      const raw = JSON.stringify([{ providerId: 'authGoogle', providerSub: 'sub-1', addedAt: 1234 }])
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'authGoogle', providerSub: 'sub-1', addedAt: 1234 }])
    })

    it('link without providerSub (optional field)', () => {
      const raw = JSON.stringify([{ providerId: 'magic-link', addedAt: 5678 }])
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'magic-link', addedAt: 5678 }])
    })

    it('multiple links', () => {
      const raw = JSON.stringify([
        { providerId: 'authGoogle', providerSub: 'sub-1', addedAt: 1 },
        { providerId: 'authGithub', providerSub: 'sub-2', addedAt: 2 },
      ])
      expect(authParseProviderLinks(raw)).toHaveLength(2)
    })
  })

  describe('filters individual malformed entries', () => {
    it('drops entry missing providerId; keeps the rest', () => {
      const raw = JSON.stringify([
        { providerId: 'authGoogle', addedAt: 1 },
        { addedAt: 2 }, // missing providerId
        { providerId: 'authGithub', addedAt: 3 },
      ])
      const result = authParseProviderLinks(raw)
      expect(result).toHaveLength(2)
      expect(result.map((p) => p.providerId)).toEqual(['authGoogle', 'authGithub'])
    })

    it('drops entry with non-string providerId', () => {
      const raw = JSON.stringify([
        { providerId: 'authGoogle', addedAt: 1 },
        { providerId: 42, addedAt: 2 }, // number
      ])
      const result = authParseProviderLinks(raw)
      expect(result).toHaveLength(1)
      expect(result[0]!.providerId).toBe('authGoogle')
    })

    it('drops entry with empty-string providerId', () => {
      const raw = JSON.stringify([
        { providerId: '', addedAt: 1 },
        { providerId: 'authGithub', addedAt: 2 },
      ])
      expect(authParseProviderLinks(raw)).toHaveLength(1)
    })

    it('drops entry with non-string providerSub', () => {
      const raw = JSON.stringify([{ providerId: 'authGoogle', providerSub: 42, addedAt: 1 }])
      expect(authParseProviderLinks(raw)).toEqual([])
    })

    it('drops entry with non-finite addedAt (NaN, Infinity, string)', () => {
      const goodArr = [{ providerId: 'authGoogle', addedAt: 1 }]
      const goodRaw = JSON.stringify(goodArr)
      expect(authParseProviderLinks(goodRaw)).toEqual(goodArr)
      // NaN / Infinity round-trip to `null` via JSON.stringify, so we
      // must inject them via raw strings.
      expect(authParseProviderLinks('[{"providerId":"authGoogle","addedAt":NaN}]')).toEqual([])
      expect(authParseProviderLinks('[{"providerId":"authGoogle","addedAt":"yesterday"}]')).toEqual([])
    })

    it('defaults missing addedAt to 0 (legacy-row tolerance)', () => {
      const raw = JSON.stringify([{ providerId: 'legacy' }])
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'legacy', addedAt: 0 }])
    })

    it('accepts addedAt === 0 (epoch start - corner case)', () => {
      const raw = JSON.stringify([{ providerId: 'epoch', addedAt: 0 }])
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'epoch', addedAt: 0 }])
    })

    it('drops `null` entries inside the array', () => {
      const raw = '[null, {"providerId":"good","addedAt":1}, null]'
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'good', addedAt: 1 }])
    })

    it('drops primitives (number, string, boolean) inside the array', () => {
      const raw = '[42, "oops", true, {"providerId":"good","addedAt":1}]'
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'good', addedAt: 1 }])
    })

    it('drops nested-array entries', () => {
      const raw = JSON.stringify([['nested'], { providerId: 'good', addedAt: 1 }])
      expect(authParseProviderLinks(raw)).toEqual([{ providerId: 'good', addedAt: 1 }])
    })
  })
})
