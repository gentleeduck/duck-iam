import { describe, expect, it, vi } from 'vitest'
import { IamHttpAdapter } from '../index'

// Pins that numeric options refuse `NaN` and out-of-range values, as `Number(process.env.X)` of an unset var gives;
// `retries: NaN` would otherwise send no request at all.
const BASE = 'https://iam.example.com'

const config = (extra: Record<string, unknown>) => ({
  allowedHosts: ['iam.example.com'],
  baseUrl: BASE,
  fetch: vi.fn(),
  ...extra,
})

describe('a numeric option that would disable what it configures is refused', () => {
  const cases: [string, unknown][] = [
    ['retries', Number.NaN],
    ['retries', -1],
    ['retries', 1.5],
    ['timeoutMs', Number.NaN],
    ['timeoutMs', -1],
    ['backoffMs', Number.NaN],
    ['circuitBreakerThreshold', 0],
    ['circuitBreakerThreshold', Number.NaN],
    ['circuitBreakerCooldownMs', Number.NaN],
  ]

  for (const [name, value] of cases) {
    // `String`, not `JSON.stringify`: the latter renders NaN as `null`.
    it(`${name}: ${String(value)} throws at construction, naming the option`, () => {
      // Malformed on purpose: `NaN` satisfies the declared `number` type, as an unset env var does.
      expect(() => new IamHttpAdapter(config({ [name]: value }))).toThrow(new RegExp(`\`${name}\``))
    })
  }

  it('accepts the values that mean something', () => {
    expect(
      () =>
        new IamHttpAdapter(
          config({
            backoffMs: 0,
            circuitBreakerCooldownMs: 0,
            circuitBreakerThreshold: 1,
            retries: 0,
            timeoutMs: 0,
          }),
        ),
    ).not.toThrow()
  })

  it('omitting them all still works', () => {
    expect(() => new IamHttpAdapter(config({}))).not.toThrow()
  })

  it('a fractional millisecond is allowed - only counts must be integers', () => {
    expect(() => new IamHttpAdapter(config({ backoffMs: 12.5, timeoutMs: 1500.5 }))).not.toThrow()
  })
})

describe('a request is attempted at least once', () => {
  it('retries: 0 still performs one fetch', async () => {
    const fetchFn = vi.fn(async () => new Response(JSON.stringify([]), { status: 200 }))
    const adapter = new IamHttpAdapter(config({ fetch: fetchFn, retries: 0 }))
    await adapter.listPolicies()
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })
})
