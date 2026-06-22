import { describe, expect, it } from 'vitest'
import { iamExtractEnvironment } from '../index'

describe('iamExtractEnvironment XFF normalization', () => {
  it('takes the leftmost IP from a multi-proxy XFF', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 10.0.0.1' } })
    expect(env.ip).toBe('1.2.3.4')
  })

  it('trims whitespace around the leftmost entry', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '   1.2.3.4   ' } })
    expect(env.ip).toBe('1.2.3.4')
  })

  it('handles single-entry XFF unchanged (most common case)', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '203.0.113.1' } })
    expect(env.ip).toBe('203.0.113.1')
  })

  it('preserves IPv6 bracketed form', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '[2001:db8::1], 10.0.0.1' } })
    expect(env.ip).toBe('[2001:db8::1]')
  })

  it('preserves IPv6 unbracketed form', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '2001:db8::1' } })
    expect(env.ip).toBe('2001:db8::1')
  })

  it('prefers req.ip over XFF when set (framework-trusted value wins)', () => {
    const env = iamExtractEnvironment({ ip: '10.0.0.1', headers: { 'x-forwarded-for': '1.2.3.4' } })
    expect(env.ip).toBe('10.0.0.1')
  })

  it('falls back to x-real-ip when XFF is absent', () => {
    const env = iamExtractEnvironment({ headers: { 'x-real-ip': '203.0.113.1' } })
    expect(env.ip).toBe('203.0.113.1')
  })

  it('applies normalization to x-real-ip too', () => {
    const env = iamExtractEnvironment({ headers: { 'x-real-ip': '  1.2.3.4  , 5.6.7.8' } })
    expect(env.ip).toBe('1.2.3.4')
  })

  it('returns undefined when XFF + x-real-ip both empty', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '', 'x-real-ip': '' } })
    expect(env.ip).toBeUndefined()
  })

  it('returns undefined when XFF leftmost is whitespace-only', () => {
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': '   ,1.2.3.4' } })
    expect(env.ip).toBeUndefined()
  })

  it('rejects oversize XFF (>4096 chars) entirely', () => {
    const big = '1.2.3.4,'.repeat(1000)
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': big } })
    expect(env.ip).toBeUndefined()
  })

  it('rejects an oversize leftmost entry (>256 chars)', () => {
    const long = 'A'.repeat(257) + ',1.2.3.4'
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': long } })
    expect(env.ip).toBeUndefined()
  })

  it('accepts a 256-char leftmost entry (boundary)', () => {
    const sized = 'A'.repeat(256) + ',1.2.3.4'
    const env = iamExtractEnvironment({ headers: { 'x-forwarded-for': sized } })
    expect(env.ip).toBe('A'.repeat(256))
  })

  it('handles array-shaped header value (Node.js req.headers)', () => {
    const env = iamExtractEnvironment({
      headers: { 'x-forwarded-for': ['1.2.3.4, 5.6.7.8'] },
    })
    expect(env.ip).toBe('1.2.3.4')
  })

  it('handles Headers instance', () => {
    const h = new Headers({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' })
    const env = iamExtractEnvironment({ headers: h })
    expect(env.ip).toBe('1.2.3.4')
  })

  it('returns undefined when no source provides IP', () => {
    const env = iamExtractEnvironment({})
    expect(env.ip).toBeUndefined()
  })
})
