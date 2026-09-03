/**
 * Boot/health/dispose helpers. The healthCheck logic is a pure
 * function of (adapter probe, stats snapshot) so it's trivially
 * unit-testable.
 */

import { aggregateCacheHitRate, type IIamCachesForStats, statsSnapshot } from './engine.stats'
import type { IamEngineTypes } from './engine.types'

/**
 * Probe the adapter and report health alongside the current cache hit rate.
 *
 * `adapterLatencyMs` times the probe, not a real query, so it is a liveness
 * signal rather than a performance measurement. A failed probe is reported as
 * `ok: false` with the message, never thrown: a health endpoint that throws
 * tells a load balancer nothing it can act on.
 *
 * @param caches - Caches to snapshot for the hit rate.
 * @param probe  - Adapter round trip; rejecting means unhealthy.
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
 * Warm the engine before it serves traffic: policies always, the validator and
 * the compiled table only if this engine uses them.
 *
 * All of it runs concurrently, since the tasks are independent and the point is
 * to move the first request's latency into startup.
 *
 * @param args - What to warm. `loadValidator` pulls in the lazily-imported
 *               validate module; `buildCompiledTable` is omitted when the
 *               engine does not compile.
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
 * Unsubscribe from the invalidator during teardown.
 *
 * A throw from the unsubscribe is dropped: this runs while the engine is
 * already being torn down, and failing here would mask whatever the caller was
 * actually shutting down for.
 *
 * @param invalidatorUnsub - The stored unsubscribe, or `null` if never subscribed.
 * @returns The cleared handle, for the caller to store back.
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
