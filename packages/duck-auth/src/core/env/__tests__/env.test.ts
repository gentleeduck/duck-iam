import { describe, expect, it, vi } from 'vitest'
import { isProduction, resolveEnv } from '../env'

describe('resolveEnv', () => {
  it.each([
    ['development', 'development'],
    ['test', 'test'],
    ['production', 'production'],
  ])('NODE_ENV=%s reads as %s', (value, expected) => {
    vi.stubEnv('NODE_ENV', value)
    expect(resolveEnv()).toBe(expected)
  })

  // Production is the default, so a deploy that forgets NODE_ENV, or spells it its own way, keeps every check.
  it.each([undefined, '', 'staging', 'dev', 'Development', 'TEST'])('NODE_ENV=%j reads as production', (value) => {
    vi.stubEnv('NODE_ENV', value)
    expect(resolveEnv()).toBe('production')
    expect(isProduction()).toBe(true)
  })

  it.each(['development', 'test'])('NODE_ENV=%s is not production', (value) => {
    vi.stubEnv('NODE_ENV', value)
    expect(isProduction()).toBe(false)
  })

  it('reads NODE_ENV on every call', () => {
    vi.stubEnv('NODE_ENV', 'development')
    expect(resolveEnv()).toBe('development')
    vi.stubEnv('NODE_ENV', 'production')
    expect(resolveEnv()).toBe('production')
  })
})
