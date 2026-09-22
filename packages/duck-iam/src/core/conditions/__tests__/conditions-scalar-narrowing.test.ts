import { describe, expect, it } from 'vitest'
import type { IamPrimitives } from '../../types'
import { ops } from '../conditions.libs'

const asAV = (v: unknown): IamPrimitives.AttributeValue => v as IamPrimitives.AttributeValue

describe('condition ops Scalar narrowing', () => {
  describe('in', () => {
    it('returns false when field is a non-Scalar object and value is a Scalar array', () => {
      expect(ops.in({ tier: 'gold' }, ['gold', 'silver'])).toBe(false)
    })

    it('returns false when value is not an array', () => {
      expect(ops.in('gold', 'gold,silver')).toBe(false)
    })

    it('matches array-field if any element is a Scalar in value', () => {
      expect(ops.in(asAV(['gold', { x: 1 }]), ['gold', 'silver'])).toBe(true)
    })

    it('returns true for scalar field present in value', () => {
      expect(ops.in('gold', ['gold', 'silver'])).toBe(true)
    })

    it('returns false for object field not in value (no SameValueZero false-positive)', () => {
      expect(ops.in({ a: 1 }, asAV([{ a: 1 }]))).toBe(false)
    })
  })

  describe('nin', () => {
    it('returns true when field is a non-Scalar object (never in a scalar list)', () => {
      expect(ops.nin({ tier: 'gold' }, ['gold', 'silver'])).toBe(true)
    })

    it('returns true when value is not an array', () => {
      expect(ops.nin('gold', 'gold,silver')).toBe(true)
    })

    it('returns true when array-field has only non-Scalars', () => {
      expect(ops.nin(asAV([{ x: 1 }, { y: 2 }]), ['gold'])).toBe(true)
    })
  })

  describe('contains', () => {
    it('returns false when value is non-Scalar and field is an array', () => {
      expect(ops.contains(['gold', 'silver'], { tier: 'gold' })).toBe(false)
    })

    it('returns true when value is a Scalar present in array-field', () => {
      expect(ops.contains(['gold', 'silver'], 'gold')).toBe(true)
    })

    it('returns false when value is a Scalar but field is non-string non-array', () => {
      expect(ops.contains(42, 'gold')).toBe(false)
    })

    it('does not substring-match when both sides are strings', () => {
      expect(ops.contains('gold-medal', 'gold')).toBe(false)
    })
  })

  describe('not_contains', () => {
    it('returns true when value is non-Scalar (never in any array)', () => {
      expect(ops.not_contains(['gold'], { tier: 'gold' })).toBe(true)
    })

    it('returns false when value is a Scalar present in array-field', () => {
      expect(ops.not_contains(['gold', 'silver'], 'gold')).toBe(false)
    })

    // SECURITY: a present non-array field fails the guard, or the `contains` type confusion bypasses this in reverse.
    it('returns false for a present non-array field', () => {
      expect(ops.not_contains(42, 'gold')).toBe(false)
      expect(ops.not_contains('gold-medal', 'gold')).toBe(false)
    })

    // `resolve()` maps a missing attribute to `null`; `undefined` is outside
    // `AttributeValue`, so the operator's `undefined` arm is belt-and-braces.
    it('returns true for an absent field', () => {
      expect(ops.not_contains(null, 'gold')).toBe(true)
    })
  })
})
