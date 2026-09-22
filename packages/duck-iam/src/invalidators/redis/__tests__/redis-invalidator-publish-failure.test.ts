import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

/** Pub/sub stub whose `publish` always throws, simulating a Redis outage. */
function makeFailingBus(thrown: unknown): IamRedisInvalidator.IPubSubLike {
  return {
    publish() {
      throw thrown
    },
    subscribe() {},
    unsubscribe() {},
  }
}

function uniqueChannel(): string {
  return `t-pubfail-${Math.random().toString(36).slice(2)}`
}

describe('createIamRedisInvalidator publish failure', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('routes a publish failure to onPublishError with the effective channel', () => {
    const channel = uniqueChannel()
    const boom = new Error('READONLY You cannot write against a read only replica')
    const seen: Array<{ message: string; channel: string }> = []
    const inv = createIamRedisInvalidator({
      channel,
      client: makeFailingBus(boom),
      onPublishError: (err, ch) => seen.push({ channel: ch, message: err.message }),
      secret: 'shared-secret',
    })

    inv.publish({ kind: 'all' })

    expect(seen).toEqual([{ channel, message: boom.message }])
  })

  it('does not throw to the caller - a lost broadcast must not fail the local mutation', () => {
    const inv = createIamRedisInvalidator({
      channel: uniqueChannel(),
      client: makeFailingBus(new Error('connection lost')),
      secret: 'shared-secret',
    })
    expect(() => inv.publish({ kind: 'subject', subjectId: 'user-1' })).not.toThrow()
  })

  it('wraps a non-Error thrown value before handing it to onPublishError', () => {
    const seen: Error[] = []
    const inv = createIamRedisInvalidator({
      channel: uniqueChannel(),
      client: makeFailingBus('string failure'),
      onPublishError: (err) => seen.push(err),
      secret: 'shared-secret',
    })

    inv.publish({ kind: 'policies' })

    expect(seen).toHaveLength(1)
    expect(seen[0]).toBeInstanceOf(Error)
    expect(seen[0]?.message).toBe('string failure')
  })

  it('warns when no onPublishError hook is configured (failure is never silent)', () => {
    const channel = uniqueChannel()
    const inv = createIamRedisInvalidator({
      channel,
      client: makeFailingBus(new Error('connection lost')),
      secret: 'shared-secret',
    })

    inv.publish({ kind: 'all' })

    const warns = (warnSpy.mock.calls ?? []).map((c: unknown[]) => String(c[0]))
    expect(warns.some((w: string) => w.includes(channel) && /publish failed/.test(w))).toBe(true)
  })

  it('does not warn when the operator supplied a hook (no double reporting)', () => {
    const channel = uniqueChannel()
    const inv = createIamRedisInvalidator({
      channel,
      client: makeFailingBus(new Error('connection lost')),
      onPublishError: () => {},
      secret: 'shared-secret',
    })

    inv.publish({ kind: 'all' })

    const warns = (warnSpy.mock.calls ?? []).map((c: unknown[]) => String(c[0]))
    expect(warns.some((w: string) => w.includes(channel))).toBe(false)
  })

  it('stays fail-soft when the onPublishError hook itself throws', () => {
    const inv = createIamRedisInvalidator({
      channel: uniqueChannel(),
      client: makeFailingBus(new Error('connection lost')),
      onPublishError: () => {
        throw new Error('operator hook blew up')
      },
      secret: 'shared-secret',
    })
    expect(() => inv.publish({ kind: 'all' })).not.toThrow()
  })

  it('reports the tenant-namespaced channel, not the base channel', () => {
    const channel = uniqueChannel()
    const seen: string[] = []
    const inv = createIamRedisInvalidator({
      channel,
      client: makeFailingBus(new Error('connection lost')),
      onPublishError: (_err, ch) => seen.push(ch),
      secret: 'shared-secret',
      tenantId: 'acme',
    })

    inv.publish({ kind: 'all' })

    expect(seen).toEqual([`${channel}:tenant:acme`])
  })
})
