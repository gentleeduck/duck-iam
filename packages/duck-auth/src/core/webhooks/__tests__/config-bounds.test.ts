/** `backoffMs` is refused when it is not a usable number, with a comment saying why. The two settings
 *  beside it drive the same loop and were not checked at all. */
import { describe, expect, it, vi } from 'vitest'
import { WebhookDeliverer } from '~/core/webhooks'

const ENDPOINT = { secret: 'shhh', url: 'https://hooks.example.com/duck' }

/** The refusal's detail, or `''` when construction succeeded. An `AuthError`'s `message` is its bare
 *  code, so a regex on the thrown error would say nothing about which setting was wrong. */
function refusal(cfg: Partial<WebhookDeliverer.Cfg>): string {
  try {
    new WebhookDeliverer({ endpoints: [ENDPOINT], ...cfg })
  } catch (err) {
    return String((err as { meta: { detail: string } }).meta.detail)
  }
  return ''
}

describe('WebhookDeliverer refuses a config that would silently never deliver', () => {
  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('refuses maxAttempts of %s', (_label, value) => {
    // `while (attempt < NaN)` is false on the first pass, so the ladder never ran, no request was made
    // and the delivery was dead-lettered with `attempts: 0` and an empty `lastError`.
    expect(refusal({ maxAttempts: value })).toContain('maxAttempts')
  })

  it.each([
    ['NaN', Number.NaN],
    ['negative', -1],
    ['zero', 0],
    ['past what setTimeout can hold', 2 ** 31],
  ])('refuses a timeoutMs that is %s', (_label, value) => {
    // `setTimeout` floors a negative or non-finite delay to zero and overflows past 2^31-1 to zero too,
    // so the abort fires before the request leaves and every attempt on the ladder is spent on nothing.
    expect(refusal({ timeoutMs: value })).toContain('timeoutMs')
  })

  it('still clamps a finite maxAttempts rather than refusing it', () => {
    expect(refusal({ maxAttempts: 0 })).toBe('')
    expect(refusal({ maxAttempts: -5 })).toBe('')
    expect(refusal({ maxAttempts: 10_000 })).toBe('')
  })

  it('still refuses a backoffMs that is not a usable number', () => {
    expect(refusal({ backoffMs: Number.NaN })).toContain('backoffMs')
    expect(refusal({ backoffMs: -1 })).toContain('backoffMs')
  })

  it('accepts a config that names all three', () => {
    expect(refusal({ backoffMs: 100, maxAttempts: 3, timeoutMs: 1_000 })).toBe('')
  })

  it('a clamped maxAttempts still drives the ladder, so the loop is not vacuous', async () => {
    const fetchMock = vi.fn(async () => new Response('nope', { status: 500 }))
    const deliverer = new WebhookDeliverer({
      backoffMs: 0,
      endpoints: [ENDPOINT],
      fetch: fetchMock as unknown as typeof globalThis.fetch,
      maxAttempts: 3,
      random: () => 0,
    })
    const [delivery] = await deliverer.deliverOne('session.created', {})
    expect(delivery?.attempts).toBe(3)
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })
})
