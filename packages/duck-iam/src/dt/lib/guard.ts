import type { AccessControl } from '../../core/types'
import type { IDevtoolsEngine } from './types'

/**
 * Hard production guard for the IAM devtools — default-block.
 *
 * Returns `true` ONLY when an explicit positive `development` signal is
 * present — either the bundler set `NODE_ENV=development` or the engine was
 * constructed in `'development'` mode. Absence of any signal blocks the
 * panel so the policy/role/subject readers cannot leak into raw-browser
 * bundles that don't shim `process` or into engines that don't surface
 * `mode` (CWE-200 / CWE-489).
 *
 * No escape hatch: to use devtools in a deployed environment, run a dev
 * build behind an admin-only route.
 *
 * @param engine - The runtime engine the panel would inspect.
 * @returns `true` when devtools MAY render, `false` to block.
 */
export function isDevtoolsAllowed(engine: IDevtoolsEngine): boolean {
  // `process` may be undefined in raw-browser bundles that don't shim it;
  // "no process" is not a development signal.
  const nodeEnv: string | undefined =
    typeof process !== 'undefined' ? (process as { env?: { NODE_ENV?: string } }).env?.NODE_ENV : undefined

  // A bundler-set production signal always blocks, regardless of engine mode.
  if (nodeEnv === 'production') return false

  // Positive development signals — either side is sufficient.
  if (nodeEnv === 'development') return true

  const mode = readEngineMode(engine)
  if (mode === 'development') return true

  // No positive signal (or engine reports production / unknown) → BLOCK.
  return false
}

/**
 * Back-compat name kept for any external callers. Inverse of
 * {@link isDevtoolsAllowed} — `true` means "do NOT mount".
 *
 * @deprecated Prefer {@link isDevtoolsAllowed} for clarity.
 */
export function isDevtoolsBlocked(engine: IDevtoolsEngine): boolean {
  return !isDevtoolsAllowed(engine)
}

function readEngineMode(engine: IDevtoolsEngine): AccessControl.Mode | undefined {
  const candidate = engine as {
    mode?: unknown
    config?: { mode?: unknown }
    _mode?: unknown
  }
  const raw = candidate.mode ?? candidate.config?.mode ?? candidate._mode
  if (raw === 'production' || raw === 'development') return raw
  return undefined
}
