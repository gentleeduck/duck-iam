import { describe, expect, it } from 'vitest'
import { isSafeCallbackPath } from '../url-validators'

describe('isSafeCallbackPath', () => {
  describe('accepts safe same-origin paths', () => {
    it.each([
      ['/'],
      ['/auth/reset-password'],
      ['/auth/verify-email'],
      ['/auth/delete-account'],
      ['/path/with/segments'],
      ['/path?existing=query'],
      ['/path#fragment'],
      ['/path/with-@-in-segment'],
      ['/a:b'],
      // 256 chars exactly
      [`/${'a'.repeat(255)}`],
    ])('accepts %s', (value) => {
      expect(isSafeCallbackPath(value)).toBe(true)
    })
  })

  describe('rejects userinfo-injection (the bug)', () => {
    it.each([
      ['@evil.com'],
      ['@evil.com/grab'],
      ['evil.com'],
      ['attacker.example'],
      ['user@evil.com'],
      ['app.example.com@evil.com'],
    ])('rejects %s (no leading slash -> slips into authority)', (value) => {
      expect(isSafeCallbackPath(value)).toBe(false)
    })
  })

  describe('rejects protocol-relative URLs', () => {
    it.each([
      ['//evil.com'],
      ['//evil.com/grab'],
      ['///evil.com'],
    ])('rejects %s (browser resolves under current scheme)', (value) => {
      expect(isSafeCallbackPath(value)).toBe(false)
    })
  })

  describe('rejects backslash-escape forms', () => {
    it.each([['/\\evil.com'], ['/\\\\evil.com'], ['/\\']])('rejects %s (some browsers normalize \\ to /)', (value) => {
      expect(isSafeCallbackPath(value)).toBe(false)
    })
  })

  describe('rejects header / template-injection chars', () => {
    it.each([
      ['/path\r\nLocation: https://evil'],
      ['/path\r'],
      ['/path\n'],
      ['/\rfoo'],
      ['/\nfoo'],
    ])('rejects %s (CR/LF)', (value) => {
      expect(isSafeCallbackPath(value)).toBe(false)
    })

    it.each([
      ['/path\tHost: evil'],
      ['/path\x00trunc'],
      ['/path\x1bescape'],
      ['/path\x7fdel'],
    ])('rejects %s (C0 control / DEL)', (value) => {
      expect(isSafeCallbackPath(value)).toBe(false)
    })
  })

  describe('rejects malformed inputs', () => {
    it.each<[unknown]>([
      [''],
      [undefined],
      [null],
      [42],
      [{ path: '/foo' }],
      [['/foo']],
      [true],
    ])('rejects %p (non-string or empty)', (value) => {
      expect(isSafeCallbackPath(value)).toBe(false)
    })
  })

  describe('rejects oversize paths', () => {
    it('rejects 257-char paths (just over cap)', () => {
      expect(isSafeCallbackPath(`/${'a'.repeat(256)}`)).toBe(false)
    })

    it('rejects 10kb paths (resource exhaustion)', () => {
      expect(isSafeCallbackPath(`/${'a'.repeat(10_000)}`)).toBe(false)
    })
  })

  describe('type predicate narrows', () => {
    it('narrows unknown -> string in the true branch', () => {
      const v: unknown = '/AUTH/reset-password'
      if (isSafeCallbackPath(v)) {
        // If the predicate works, `v.startsWith` compiles without a cast.
        expect(v.startsWith('/')).toBe(true)
      } else {
        throw new Error('expected predicate to narrow')
      }
    })
  })
})
