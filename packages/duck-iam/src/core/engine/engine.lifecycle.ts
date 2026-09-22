// Boot, health and dispose helpers, testable without an engine.

import type { AccessControl } from '../types'
import type { IamValidate } from '../validate/validate.types'
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

/** At most this many offending rows are named in the preload error; the count is always exact. */
const PRELOAD_REPORT_LIMIT = 10

/**
 * Warms policies, plus the lazily imported validator and the compiled table when this engine uses them.
 * Runs everything concurrently to move first-request latency into startup.
 * SECURITY: with `loadValidator`, every stored policy and role is validated and a failure throws. Only the write
 * path validates otherwise, so a row that entered storage another way runs unchecked — a deny whose condition the
 * validator would have refused never fires.
 */
export async function preloadEngine(args: {
  loadAllPolicies: () => Promise<readonly AccessControl.IPolicy[]>
  loadAllRoles: () => Promise<readonly AccessControl.IRole[]>
  loadValidator: boolean
  buildCompiledTable?: () => Promise<unknown>
}): Promise<void> {
  const [policies, roles, validate] = await Promise.all([
    args.loadAllPolicies(),
    args.loadValidator ? args.loadAllRoles() : undefined,
    args.loadValidator ? import('../validate') : undefined,
    args.buildCompiledTable?.(),
  ])
  if (validate === undefined || roles === undefined) return

  const problems: string[] = []
  const record = (kind: 'policy' | 'role', id: string, result: IamValidate.IResult): void => {
    if (result.valid) return
    const why = result.issues
      .filter((i) => i.type === 'error')
      .map((i) => i.message)
      .join('; ')
    problems.push(`${kind} "${id}": ${why}`)
  }
  for (const policy of policies) record('policy', policy.id, validate.validatePolicy(policy))
  for (const role of roles) record('role', role.id, validate.validateRole(role))

  if (problems.length === 0) return
  const shown = problems.slice(0, PRELOAD_REPORT_LIMIT).join(' | ')
  const more = problems.length > PRELOAD_REPORT_LIMIT ? ` (+${problems.length - PRELOAD_REPORT_LIMIT} more)` : ''
  throw new Error(
    `[@gentleduck/iam:engine] preload({ validator: true }): ${problems.length} stored row(s) are invalid: ${shown}${more}`,
  )
}

/**
 * Unsubscribes from the invalidator and returns the cleared handle to store back.
 * NOTE: a throw is reported rather than raised, so it cannot mask the reason for shutting down - but never
 * dropped: a teardown that failed may leave the subscription delivering into an engine already released.
 */
export function disposeInvalidator(invalidatorUnsub: (() => void) | null): { unsub: (() => void) | null } {
  if (invalidatorUnsub) {
    try {
      invalidatorUnsub()
    } catch (err) {
      try {
        console.warn(
          '[@gentleduck/iam:engine] the invalidator teardown threw; this engine may keep receiving invalidations ' +
            `after being released. (${err instanceof Error ? err.message : String(err)})`,
        )
      } catch {}
    }
  }
  return { unsub: null }
}
