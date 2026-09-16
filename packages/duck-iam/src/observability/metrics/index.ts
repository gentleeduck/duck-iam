import type { IamEngineTypes } from '../../core/engine/engine.types'

/** IamMetrics observability types. Type-only namespace - zero bundle cost. */
export namespace IamMetrics {
  /**
   * Aggregates the engine's `onMetrics` events in-process: wire `.record` into `hooks.onMetrics` and read
   * `.snapshot()` on demand. A fixed-size ring of recent durations gives p50 / p95 / p99 with no histogram library.
   */
  export interface IAggregator {
    /**
     * Records a single metrics event. Bind directly to {@link IamEngineTypes.IHooks.onMetrics}.
     *
     * @param event - Receives the metrics event emitted by the engine after every check.
     */
    record(event: IamEngineTypes.IMetricsEvent): void
    /**
     * Computes the current rolling snapshot. Callers can poll at any interval.
     *
     * @returns Immutable {@link ISnapshot} summarising the rolling window.
     */
    snapshot(): ISnapshot
    /** Resets counters and clears the rolling sample buffer. */
    reset(): void
  }

  /** Immutable snapshot of aggregated metrics over the rolling window. */
  export interface ISnapshot {
    /** Total events recorded since the last reset. */
    readonly total: number
    /** Number of allow verdicts. */
    readonly allow: number
    /** Number of deny verdicts. */
    readonly deny: number
    /**
     * Allow verdicts from the `defaultEffect: 'allow'` fallback alone, a subset of {@link allow}.
     * WARN: chart this - a rise means no policy is firing, which is silent policy-set breakage.
     */
    readonly failOpen: number
    /** p50 latency in milliseconds over the rolling window. */
    readonly p50: number
    /** p95 latency in milliseconds over the rolling window. */
    readonly p95: number
    /** p99 latency in milliseconds over the rolling window. */
    readonly p99: number
    /** Maximum latency in the rolling window. */
    readonly max: number
    /** Window size (capped by the configured `sampleSize`). */
    readonly samples: number
  }

  /** Configures {@link iamCreateMetricsAggregator}. */
  export interface IConfig {
    /**
     * Duration samples kept in the rolling window; a positive integer, `1000` by default.
     * PERF: a larger window buys tail-percentile accuracy with memory and a longer sort per snapshot.
     */
    sampleSize?: number
  }
}

/**
 * Creates an in-process metrics aggregator: a fixed-size ring buffer for latency percentiles and running allow/deny
 * counters. Bind `.record` to {@link IamEngineTypes.IHooks.onMetrics} and read `.snapshot()` on demand.
 *
 * @param config - Optionally overrides the sample size; see {@link IamMetrics.IConfig}.
 * @returns A new {@link IamMetrics.IAggregator} instance with zeroed counters.
 * @example
 * ```ts
 * const metrics = iamCreateMetricsAggregator({ sampleSize: 2000 })
 * const engine = new IamEngine({ adapter, hooks: { onMetrics: metrics.record } })
 * app.get('/metrics', (_, res) => res.json(metrics.snapshot()))
 * ```
 */
export function iamCreateMetricsAggregator(config: IamMetrics.IConfig = {}): IamMetrics.IAggregator {
  const cap = config.sampleSize ?? 1000
  if (!Number.isInteger(cap) || cap < 1) {
    throw new RangeError(`[@gentleduck/iam:metrics] sampleSize must be a positive integer (got ${String(cap)})`)
  }
  const buf = new Float64Array(cap)
  let head = 0
  let count = 0
  let total = 0
  let allow = 0
  let deny = 0
  let failOpen = 0

  return {
    record(event) {
      total++
      if (event.allowed) allow++
      else deny++
      if (event.failOpen) failOpen++
      // WARN: the verdict is always counted, but a `NaN` duration would make the percentile comparator inconsistent
      // and poison every quantile until the ring rolls over, so bad samples are dropped and `samples` <= `total`.
      if (Number.isFinite(event.durationMs) && event.durationMs >= 0) {
        buf[head] = event.durationMs
        head = (head + 1) % cap
        if (count < cap) count++
      }
    },
    snapshot() {
      if (count === 0) {
        return { total, allow, deny, failOpen, p50: 0, p95: 0, p99: 0, max: 0, samples: 0 }
      }
      // PERF: O(n log n) per snapshot, which is fine at the default cap and avoids a streaming-quantile dependency.
      const sorted = Array.from(buf.subarray(0, count))
      sorted.sort((a, b) => a - b)
      return {
        total,
        allow,
        deny,
        failOpen,
        p50: percentile(sorted, 0.5),
        p95: percentile(sorted, 0.95),
        p99: percentile(sorted, 0.99),
        max: sorted[sorted.length - 1] ?? 0,
        samples: count,
      }
    },
    reset() {
      head = 0
      count = 0
      total = 0
      allow = 0
      deny = 0
      failOpen = 0
    },
  }
}

function percentile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0
  const i = Math.max(0, Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1))
  return sorted[i] ?? 0
}
