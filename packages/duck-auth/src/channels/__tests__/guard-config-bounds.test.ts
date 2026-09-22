/** `ChannelGuard` carries the same retry ladder `AuthWebhookDeliverer` does, and took `retries` and
 *  `timeoutMs` on trust. Both decide whether a password reset or a magic link ever leaves the process. */

import { describe, expect, it, vi } from 'vitest'
import { ChannelGuard } from '../channels.guard'

/** The `detail`, since `AuthError.message` is the bare code and never carries one. */
function refusal(cfg: ChannelGuard.Cfg): string {
  try {
    new ChannelGuard('test', cfg)
  } catch (err) {
    return err instanceof Error && 'meta' in err ? String((err.meta as { detail?: unknown }).detail) : String(err)
  }
  throw new Error('expected the guard to refuse this config')
}

describe('ChannelGuard config bounds', () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 21])('refuses retries %p', (value) => {
    expect(refusal({ retries: value })).toContain('retries')
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1, 2 ** 31])('refuses timeoutMs %p', (value) => {
    expect(refusal({ timeoutMs: value })).toContain('timeoutMs')
  })

  it('accepts the defaults, and the documented zeroes', () => {
    expect(() => new ChannelGuard('test', {})).not.toThrow()
    // `retries: 0` sends exactly once, `timeoutMs: 0` disables the deadline; both are documented.
    expect(() => new ChannelGuard('test', { retries: 0, timeoutMs: 0 })).not.toThrow()
  })

  it('still sends exactly once at retries 0', async () => {
    const call = vi.fn(async () => 'sent')
    await expect(new ChannelGuard('test', { retries: 0 }).attempt(call)).resolves.toBe('sent')
    expect(call).toHaveBeenCalledTimes(1)
  })

  it('still spends the whole ladder before giving up, and reports the provider error', async () => {
    const call = vi.fn(async () => {
      throw new Error('provider down')
    })

    // Two retries after the first attempt is three calls, and the last failure is what surfaces.
    await expect(new ChannelGuard('test', { retries: 2 }).attempt(call)).rejects.toThrow('provider down')
    expect(call).toHaveBeenCalledTimes(3)
  })

  it('still deadlines a provider that never answers', async () => {
    const guard = new ChannelGuard('test', { retries: 0, timeoutMs: 10 })

    await expect(guard.attempt(() => new Promise(() => {}))).rejects.toThrow(/did not answer within 10ms/)
  })
})
