// Boot, health and dispose helpers, testable without an engine.

import { aggregateCacheHitRate, type IIamCachesForStats, statsSnapshot } from './engine.stats'
import type { IamEngineTypes } from './engine.types'

/**
 * Probes the adapter and reports health with the cache hit rate. `adapterLatencyMs` is liveness, not performance.
 * NOTE: a failed probe returns `ok: false` instead of throwing, so a load balancer gets an answer it can act on.
 */
export async function runHealthCheck(
  caches: IIamCachesForStats,
  probe: () => Promise<void>,
): Promise<IamEngineTypes.IHealth> {
  const t0 = performance.now()
  let adapter: 'ok' | 'fail' = 'ok'
  let lastError: string | undefined
  try {
    await probe()
  } catch (err) {
    adapter = 'fail'
    lastError = err instanceof Error ? err.message : String(err)
  }
  const s = statsSnapshot(caches)
  const { rate } = aggregateCacheHitRate(s)
  return {
    ok: adapter === 'ok',
    adapter,
    cacheHitRate: rate,
    adapterLatencyMs: Math.round(performance.now() - t0),
    ...(lastError !== undefined && { lastError }),
  }
}

/**
 * Warms policies, plus the lazily imported validator and the compiled table when this engine uses them.
 * Runs everything concurrently to move first-request latency into startup.
 */
export async function preloadEngine(args: {
  loadAllPolicies: () => Promise<unknown>
  loadValidator: boolean
  buildCompiledTable?: () => Promise<unknown>
}): Promise<void> {
  const tasks: Array<Promise<unknown>> = [args.loadAllPolicies()]
  if (args.loadValidator) tasks.push(import('../validate'))
  if (args.buildCompiledTable) tasks.push(args.buildCompiledTable())
  await Promise.all(tasks)
}

/**
 * Unsubscribes from the invalidator and returns the cleared handle to store back.
 * NOTE: a throw is dropped so it cannot mask the reason for shutting down.
 */
export function disposeInvalidator(invalidatorUnsub: (() => void) | null): { unsub: (() => void) | null } {
  if (invalidatorUnsub) {
    try {
      invalidatorUnsub()
    } catch {
      /* last-resort: drop the throw, we're already tearing down */
    }
  }
  return { unsub: null }
}
