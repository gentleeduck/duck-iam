import React from 'react'
import type { IamMetrics } from '../../observability/metrics'
import type { IamIDevtoolsEngine, IamIDevtoolsMetrics } from './types'

/**
 * Shared poll loop behind the Telemetry panel (v1 and v2): re-reads the engine's cache stats and the
 * optional metrics aggregator every `pollMs`, and exposes a `reset` that clears both and re-reads immediately.
 * PERF: polls instead of hooking each decision, so devtools rendering stays off the authorization hot path.
 */
export function useIamMetricsPanel(
  engine: IamIDevtoolsEngine,
  metrics: IamIDevtoolsMetrics | undefined,
  pollMs: number,
) {
  const [stats, setStats] = React.useState(() => engine.stats.get())
  const [snapshot, setSnapshot] = React.useState<IamMetrics.ISnapshot | null>(() => metrics?.snapshot() ?? null)

  React.useEffect(() => {
    const id = setInterval(() => {
      setStats(engine.stats.get())
      if (metrics) setSnapshot(metrics.snapshot())
    }, pollMs)
    return () => clearInterval(id)
  }, [engine, metrics, pollMs])

  const reset = () => {
    engine.stats.reset()
    metrics?.reset()
    setStats(engine.stats.get())
    setSnapshot(metrics?.snapshot() ?? null)
  }

  const allowRate = snapshot && snapshot.total > 0 ? Math.round((snapshot.allow / snapshot.total) * 100) : 0

  return { allowRate, reset, snapshot, stats }
}
