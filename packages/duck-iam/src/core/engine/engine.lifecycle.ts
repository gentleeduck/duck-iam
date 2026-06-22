/**
 * Boot/health/dispose helpers. The healthCheck logic is a pure
 * function of (adapter probe, stats snapshot) so it's trivially
 * unit-testable.
 */

import { aggregateCacheHitRate, type IIamCachesForStats, statsSnapshot } from './engine.stats'
import type { IamEngineTypes } from './engine.types'

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

export async function preloadEngine(args: {
  loadAllPolicies: () => Promise<unknown>
  loadValidator: boolean
}): Promise<void> {
  const tasks: Array<Promise<unknown>> = [args.loadAllPolicies()]
  if (args.loadValidator) tasks.push(import('../validate'))
  await Promise.all(tasks)
}

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
