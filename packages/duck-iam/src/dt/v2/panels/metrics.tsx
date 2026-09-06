'use client'

import { cn } from '@gentleduck/libs/cn'
import { Gauge, RotateCcw } from 'lucide-react'
import React from 'react'
import { isDevtoolsAllowed } from '../../lib/guard'
import type { IamIDevtoolsEngine, IamIDevtoolsMetrics } from '../../lib/types'
import {
  IamV2Action,
  IamV2Chip,
  IamV2Empty,
  IamV2Meter,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Section,
  IamV2Stat,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_MONO, type IamV2Tone } from '../lib/tone'

/** Hit rate as a band, so a cold cache is visible without reading the number. */
function rateTone(percent: number): IamV2Tone {
  if (percent > 80) return 'allow'
  if (percent > 50) return 'info'
  return 'warn'
}

/** One cache: its hit rate on a real `Progress`, its size, and the raw counts. */
function CacheCard({ hits, misses, name, size }: { hits: number; misses: number; name: string; size: number }) {
  const total = hits + misses
  const percent = total > 0 ? Math.round((hits / total) * 100) : 0
  return (
    <IamV2Meter
      caption={`${size} entries · ${hits} hits / ${misses} misses`}
      label={<code className={cn(IAM_V2_MONO, 'truncate text-foreground')}>{name}</code>}
      name={`${name} cache hit rate`}
      percent={percent}
      tone={rateTone(percent)}
    />
  )
}

/**
 * Live cache and decision counters, re-read every `pollMs`.
 *
 * Polls rather than subscribes: the engine publishes no metrics event, and a
 * hook firing per decision would put devtools rendering on the hot path of
 * every authorization check.
 */
export function IamMetricsPanelV2({
  engine,
  metrics,
  pollMs = 1000,
}: {
  engine: IamIDevtoolsEngine
  metrics?: IamIDevtoolsMetrics
  pollMs?: number
}) {
  const [stats, setStats] = React.useState(() => engine.stats.get())
  const [snapshot, setSnapshot] = React.useState(() => metrics?.snapshot() ?? null)

  React.useEffect(() => {
    const id = setInterval(() => {
      setStats(engine.stats.get())
      if (metrics) setSnapshot(metrics.snapshot())
    }, pollMs)
    return () => clearInterval(id)
  }, [engine, metrics, pollMs])

  // Below every hook. This one writes too - the reset button clears the
  // engine's own counters.
  if (!isDevtoolsAllowed(engine)) return null

  const allowRate = snapshot && snapshot.total > 0 ? Math.round((snapshot.allow / snapshot.total) * 100) : 0
  const caches = Object.entries(stats)

  return (
    <IamV2Root className="flex-1">
      <IamV2PaneHeader
        actions={
          <IamV2Action
            label="Reset counters"
            onClick={() => {
              engine.stats.reset()
              metrics?.reset()
              setStats(engine.stats.get())
              setSnapshot(metrics?.snapshot() ?? null)
            }}>
            <RotateCcw size={12} />
            reset
          </IamV2Action>
        }
        title="Telemetry"
      />
      <IamV2PaneBody>
        <IamV2Section title="Evaluations" trailing={<IamV2Chip tone="neutral">every {pollMs}ms</IamV2Chip>}>
          {!metrics ? (
            <IamV2Empty
              description="Pass metrics={aggregator} to the devtool to record evaluation counts and latency."
              icon={<Gauge />}
              title="No aggregator wired"
            />
          ) : !snapshot ? (
            <IamV2Empty description="Nothing has been evaluated yet." icon={<Gauge />} title="Waiting for a sample" />
          ) : (
            <div className="flex flex-col gap-2">
              <IamV2Meter
                caption={`${snapshot.allow} allowed · ${snapshot.deny} denied of ${snapshot.total}`}
                name="allow rate"
                percent={allowRate}
                tone={allowRate > 0 ? 'allow' : 'neutral'}
              />
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <IamV2Stat label="evaluations" value={snapshot.total} />
                <IamV2Stat hint="in window" label="samples" value={snapshot.samples} />
                <IamV2Stat label="denied" value={snapshot.deny} />
                <IamV2Stat hint="ms" label="max" value={snapshot.max.toFixed(2)} />
                <IamV2Stat hint="ms" label="p50" value={snapshot.p50.toFixed(2)} />
                <IamV2Stat hint="ms" label="p95" value={snapshot.p95.toFixed(2)} />
                <IamV2Stat hint="ms" label="p99" value={snapshot.p99.toFixed(2)} />
                <IamV2Stat hint="between polls" label="refresh" value={`${pollMs}ms`} />
              </div>
            </div>
          )}
        </IamV2Section>
        <IamV2Section title={`Caches (${caches.length})`}>
          {caches.length === 0 ? (
            <IamV2Empty description="The engine reports no caches." icon={<Gauge />} title="No caches" />
          ) : (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {caches.map(([name, cache]) => (
                <CacheCard hits={cache.hits} key={name} misses={cache.misses} name={name} size={cache.size} />
              ))}
            </div>
          )}
        </IamV2Section>
        <IamV2Section defaultOpen={false} title="Raw snapshot">
          <IamV2Json data={{ metrics: snapshot, stats }} />
        </IamV2Section>
      </IamV2PaneBody>
    </IamV2Root>
  )
}
