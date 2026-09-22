import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { iamCreateMetricsAggregator } from '../../../observability/metrics'
import type { AccessControl } from '../../types'
import type { IamEngineTypes } from '../engine.types'
import { IamEngine } from '../index'

class Breakable extends IamMemoryAdapter {
  broken = false
  override async getSubjectRoles(id: string) {
    if (this.broken) throw new Error('adapter down')
    return super.getSubjectRoles(id)
  }
}

type Seen = {
  after: AccessControl.IDecision[]
  deny: AccessControl.IDecision[]
  error: number
  metrics: IamEngineTypes.IMetricsEvent[]
}

async function make(mode: 'production' | 'development' = 'production') {
  const adapter = new Breakable()
  await adapter.saveRole({
    description: '',
    id: 'r',
    inherits: [],
    name: 'r',
    permissions: [{ action: 'read', resource: 'post' }],
  })
  await adapter.assignRole('u1', 'r')
  const seen: Seen = { after: [], deny: [], error: 0, metrics: [] }
  const engine = new IamEngine({
    adapter,
    cacheTTL: 0,
    hooks: {
      afterEvaluate: (_req, d) => {
        seen.after.push(d)
      },
      onDeny: (_req, d) => {
        seen.deny.push(d)
      },
      onError: () => {
        seen.error++
      },
      onMetrics: (e) => {
        seen.metrics.push(e)
      },
    },
    mode,
  })
  return { adapter, engine, seen }
}

const POST = { attributes: {}, type: 'post' } as const

describe('a deny the engine returned without evaluating is still observed', () => {
  it('CONTROL: an evaluated allow and an evaluated deny report as before', async () => {
    const { engine, seen } = await make()
    expect(await engine.can('u1', 'read', POST)).toBe(true)
    expect(await engine.can('u1', 'write', POST)).toBe(false)
    expect(seen.after).toHaveLength(2)
    expect(seen.deny).toHaveLength(1)
    expect(seen.metrics.map((m) => m.allowed)).toEqual([true, false])
  })

  it('can() reports a malformed subject id as a deny', async () => {
    const { engine, seen } = await make()
    expect(await engine.can('', 'read', POST)).toBe(false)
    expect(seen.after).toHaveLength(1)
    expect(seen.deny[0]?.failure).toBe('input')
    expect(seen.metrics[0]?.allowed).toBe(false)
    expect(seen.error).toBe(0)
  })

  it('can() reports an unreachable adapter as a deny, not only an error', async () => {
    const { adapter, engine, seen } = await make()
    adapter.broken = true
    expect(await engine.can('u1', 'read', POST)).toBe(false)
    expect(seen.error).toBe(1)
    expect(seen.deny[0]?.failure).toBe('resolution')
    expect(seen.metrics[0]?.allowed).toBe(false)
  })

  it.each(['production', 'development'] as const)('check() reports both fail-closed paths in %s', async (mode) => {
    const { adapter, engine, seen } = await make(mode)
    await engine.check('', 'read', POST)
    adapter.broken = true
    await engine.check('u1', 'read', POST)
    expect(seen.deny.map((d) => d.failure)).toEqual(['input', 'resolution'])
    expect(seen.metrics).toHaveLength(2)
  })

  it('permissions() reports one deny per map entry when the load fails', async () => {
    const { adapter, engine, seen } = await make()
    adapter.broken = true
    const map = await engine.permissions('u1', [
      { action: 'read', resource: 'post' },
      { action: 'write', resource: 'post' },
    ])
    expect(Object.values(map)).toEqual([false, false])
    expect(seen.error).toBe(1)
    expect(seen.deny).toHaveLength(2)
    expect(seen.metrics).toHaveLength(2)
  })

  it('permissions() reports the per-check failure too', async () => {
    const { seen } = await make()
    const throwing = new IamEngine({
      adapter: new IamMemoryAdapter(),
      cacheTTL: 0,
      hooks: {
        afterEvaluate: (_req, d) => {
          seen.after.push(d)
        },
        beforeEvaluate: (req) => {
          if (req.action === 'write') throw new Error('hook says no')
          return req
        },
        onDeny: (_req, d) => {
          seen.deny.push(d)
        },
        onMetrics: (e) => {
          seen.metrics.push(e)
        },
      },
      mode: 'production',
    })
    await throwing.permissions('u1', [
      { action: 'read', resource: 'post' },
      { action: 'write', resource: 'post' },
    ])
    expect(seen.deny.map((d) => d.failure)).toEqual([undefined, 'evaluation'])
    expect(seen.metrics).toHaveLength(2)
  })

  it('permissions({ telemetry: false }) still reports the deny, without the metric', async () => {
    const { adapter, engine, seen } = await make()
    adapter.broken = true
    await engine.permissions('u1', [{ action: 'read', resource: 'post' }], undefined, { telemetry: false })
    expect(seen.deny).toHaveLength(1)
    expect(seen.metrics).toHaveLength(0)
  })

  it('a throwing onDeny cannot turn the fail-closed deny into an allow', async () => {
    const adapter = new Breakable()
    adapter.broken = true
    const engine = new IamEngine({
      adapter,
      cacheTTL: 0,
      hooks: {
        onDeny: () => {
          throw new Error('observer exploded')
        },
      },
      mode: 'production',
    })
    expect(await engine.can('u1', 'read', POST)).toBe(false)
    expect(await engine.can('', 'read', POST)).toBe(false)
  })

  it('the aggregator counts an outage as denials instead of flatlining', async () => {
    const adapter = new Breakable()
    await adapter.saveRole({
      description: '',
      id: 'r',
      inherits: [],
      name: 'r',
      permissions: [{ action: 'read', resource: 'post' }],
    })
    await adapter.assignRole('u1', 'r')
    const metrics = iamCreateMetricsAggregator()
    const engine = new IamEngine({ adapter, cacheTTL: 0, hooks: { onMetrics: metrics.record }, mode: 'production' })
    await engine.can('u1', 'read', POST)
    adapter.broken = true
    for (let i = 0; i < 5; i++) await engine.can('u1', 'read', POST)
    const snap = metrics.snapshot()
    expect(snap.total).toBe(6)
    expect(snap.allow).toBe(1)
    expect(snap.deny).toBe(5)
    expect(snap.failOpen).toBe(0)
  })
})
