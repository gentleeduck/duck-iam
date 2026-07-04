import { describe, expect, it } from 'vitest'
import type { IamRequest } from '../../types'
import { evalConditionGroup } from '../conditions'

// Fixed clock for deterministic temporal assertions.
const NOW = Date.parse('2026-07-04T00:00:00.000Z')
const FUTURE_MS = NOW + 60_000
const PAST_MS = NOW - 60_000
const FUTURE_ISO = new Date(FUTURE_MS).toISOString()
const PAST_ISO = new Date(PAST_MS).toISOString()

function makeReq(timedOutUntil: unknown): IamRequest.IAccessRequest {
  return {
    subject: {
      id: 'user-1',
      roles: ['member'],
      attributes: { timedOutUntil: timedOutUntil as never },
    },
    action: 'sendMessages',
    resource: { type: 'message', id: 'm-1', attributes: {} },
    environment: { now: NOW },
  }
}

const after = { all: [{ field: 'subject.attributes.timedOutUntil', operator: 'after' as const, value: '$environment.now' }] }
const before = {
  all: [{ field: 'subject.attributes.timedOutUntil', operator: 'before' as const, value: '$environment.now' }],
}

describe('temporal operators: after / before', () => {
  it('after fires while an epoch-ms timestamp is still in the future', () => {
    expect(evalConditionGroup(makeReq(FUTURE_MS), after)).toBe(true)
  })

  it('after does not fire once an epoch-ms timestamp is in the past', () => {
    expect(evalConditionGroup(makeReq(PAST_MS), after)).toBe(false)
  })

  it('after coerces ISO-8601 strings on both sides', () => {
    expect(evalConditionGroup(makeReq(FUTURE_ISO), after)).toBe(true)
    expect(evalConditionGroup(makeReq(PAST_ISO), after)).toBe(false)
  })

  it('before mirrors after', () => {
    expect(evalConditionGroup(makeReq(PAST_MS), before)).toBe(true)
    expect(evalConditionGroup(makeReq(FUTURE_MS), before)).toBe(false)
    expect(evalConditionGroup(makeReq(PAST_ISO), before)).toBe(true)
  })

  it('fails closed on a missing timestamp (NaN coercion -> false)', () => {
    expect(evalConditionGroup(makeReq(undefined), after)).toBe(false)
    expect(evalConditionGroup(makeReq(null), after)).toBe(false)
    expect(evalConditionGroup(makeReq(undefined), before)).toBe(false)
  })

  it('fails closed on a non-date string (unparseable -> false)', () => {
    expect(evalConditionGroup(makeReq('not-a-date'), after)).toBe(false)
    expect(evalConditionGroup(makeReq(true), after)).toBe(false)
  })
})
