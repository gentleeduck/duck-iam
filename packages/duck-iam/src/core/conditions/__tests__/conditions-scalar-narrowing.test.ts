import { describe, expect, it } from 'vitest'
import type { IamPrimitives } from '../../types'
import { iamOps } from '../conditions.libs'

const asAV = (v: unknown): IamPrimitives.AttributeValue => v as IamPrimitives.AttributeValue

describe('condition iamOps Scalar narrowing', () => {
  describe('in', () => {
    it('returns false when field is a non-Scalar object and value is a Scalar array', () => {
      expect(iamOps.in({ tier: 'gold' }, ['gold', 'silver'])).toBe(false)
    })

    it('returns false when value is not an array', () => {
      expect(iamOps.in('gold', 'gold,silver')).toBe(false)
    })

    it('matches array-field if any element is a Scalar in value', () => {
      expect(iamOps.in(asAV(['gold', { x: 1 }]), ['gold', 'silver'])).toBe(true)
    })

    it('returns true for scalar field present in value', () => {
      expect(iamOps.in('gold', ['gold', 'silver'])).toBe(true)
    })

    it('returns false for object field not in value (no SameValueZero false-positive)', () => {
      expect(iamOps.in({ a: 1 }, asAV([{ a: 1 }]))).toBe(false)
    })
  })

  describe('nin', () => {
    it('returns true when field is a non-Scalar object (never in a scalar list)', () => {
      expect(iamOps.nin({ tier: 'gold' }, ['gold', 'silver'])).toBe(true)
    })

    it('returns true when value is not an array', () => {
      expect(iamOps.nin('gold', 'gold,silver')).toBe(true)
    })

    it('returns true when array-field has only non-Scalars', () => {
      expect(iamOps.nin(asAV([{ x: 1 }, { y: 2 }]), ['gold'])).toBe(true)
    })
  })

  describe('contains', () => {
    it('returns false when value is non-Scalar and field is an array', () => {
      expect(iamOps.contains(['gold', 'silver'], { tier: 'gold' })).toBe(false)
    })

    it('returns true when value is a Scalar present in array-field', () => {
      expect(iamOps.contains(['gold', 'silver'], 'gold')).toBe(true)
    })

    it('returns false when value is a Scalar but field is non-string non-array', () => {
      expect(iamOps.contains(42, 'gold')).toBe(false)
    })

    it('falls through to string substring when both sides are strings', () => {
      expect(iamOps.contains('gold-medal', 'gold')).toBe(true)
    })
  })

  describe('not_contains', () => {
    it('returns true when value is non-Scalar (never in any array)', () => {
      expect(iamOps.not_contains(['gold'], { tier: 'gold' })).toBe(true)
    })

    it('returns false when value is a Scalar present in array-field', () => {
      expect(iamOps.not_contains(['gold', 'silver'], 'gold')).toBe(false)
    })

    it('returns true for the no-array no-string case', () => {
      expect(iamOps.not_contains(42, 'gold')).toBe(true)
    })
  })
})
