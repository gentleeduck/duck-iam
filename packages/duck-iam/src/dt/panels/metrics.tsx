import React from 'react'
import { Refresh } from '../components/icons'
import { JsonTree } from '../components/json-tree'
import { Section } from '../components/layout'
import { Badge, Button, Empty } from '../components/ui'
import { isDevtoolsAllowed } from '../lib/guard'
import { useIamDevtoolsStyles } from '../lib/styles'
import type { IamIDevtoolsEngine, IamIDevtoolsMetrics } from '../lib/types'

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="iam-dt-stat">
      <span className="iam-dt-stat__label">{label}</span>
      <span className="iam-dt-stat__value">{value}</span>
      {hint && <span className="iam-dt-stat__hint">{hint}</span>}
    </div>
  )
}

/**
 * Live cache and decision counters, re-read every `pollMs`.
 * PERF: polls instead of hooking each decision, so devtools rendering stays off the authorization hot path.
 */
export function IamMetricsPanel({
  engine,
  metrics,
  pollMs = 1000,
}: {
  engine: IamIDevtoolsEngine
  metrics?: IamIDevtoolsMetrics
  pollMs?: number
}) {
  useIamDevtoolsStyles()
  const [stats, setStats] = React.useState(() => engine.stats.get())
  const [snap, setSnap] = React.useState(() => metrics?.snapshot() ?? null)

  React.useEffect(() => {
    const id = setInterval(() => {
      setStats(engine.stats.get())
      if (metrics) setSnap(metrics.snapshot())
    }, pollMs)
    return () => clearInterval(id)
  }, [engine, metrics, pollMs])

  // SECURITY: each panel is exported on its own, so it runs the guard itself. Kept below every hook.
  if (!isDevtoolsAllowed(engine)) return null

  const allowRate = snap && snap.total > 0 ? Math.round((snap.allow / snap.total) * 100) : 0

  return (
    <div className="iam-dt iam-dt-detail">
      <div className="iam-dt-detail__head">
        <span className="iam-dt-listshell__title">Telemetry</span>
        <Badge tone="info">poll {pollMs}ms</Badge>
        <span style={{ marginLeft: 'auto' }}>
          <Button
            onClick={() => {
              engine.stats.reset()
              metrics?.reset()
              setStats(engine.stats.get())
              setSnap(metrics?.snapshot() ?? null)
            }}>
            <Refresh size={10} /> reset
          </Button>
        </span>
      </div>
      <Section title="Evaluations">
        {!metrics ? (
          <Empty message="No metrics aggregator wired. Pass `metrics={...}` to enable telemetry." />
        ) : !snap ? (
          <Empty message="Waiting for first sample." />
        ) : (
          <div className="iam-dt-stat-grid">
            <Stat label="evals" value={snap.total} />
            <Stat hint={`${snap.allow} allow / ${snap.deny} deny`} label="allow rate" value={`${allowRate}%`} />
            <Stat hint="samples" label="window" value={snap.samples} />
            <Stat hint="ms" label="max" value={snap.max.toFixed(2)} />
            <Stat hint="ms" label="p50" value={snap.p50.toFixed(2)} />
            <Stat hint="ms" label="p95" value={snap.p95.toFixed(2)} />
            <Stat hint="ms" label="p99" value={snap.p99.toFixed(2)} />
            <Stat label="deny" value={snap.deny} />
          </div>
        )}
      </Section>
      <Section title={`Caches (${Object.keys(stats).length})`}>
        <div className="iam-dt-stat-grid">
          {Object.entries(stats).map(([name, s]) => {
            const total = s.hits + s.misses
            const hit = total > 0 ? Math.round((s.hits / total) * 100) : 0
            return (
              <div className="iam-dt-stat" key={name}>
                <div className="iam-dt-row" style={{ justifyContent: 'space-between' }}>
                  <code style={{ fontSize: 11 }}>{name}</code>
                  <Badge tone={hit > 80 ? 'allow' : hit > 50 ? 'info' : 'warn'}>{hit}%</Badge>
                </div>
                <span className="iam-dt-stat__hint" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  size {s.size}
                  <span className="iam-dt-sep" />
                  {s.hits} hits / {s.misses} miss
                </span>
              </div>
            )
          })}
        </div>
      </Section>
      <Section defaultOpen={false} title="Raw snapshot">
        <JsonTree data={{ stats, metrics: snap }} defaultOpen />
      </Section>
    </div>
  )
}
