import type { AccessControl } from '../../core/types'
import type { IDevtoolsEngine } from './types'

/**
 * Hard production guard for the IAM devtools (SEC-021: default-block).
 *
 * Returns `true` ONLY when an explicit positive `development` signal is
 * present — either the bundler set `NODE_ENV=development` or the engine was
 * constructed in `'development'` mode. Absence of any signal blocks the panel.
 *
 * Previous semantics treated "no signal" as non-production and rendered the
 * panel; that fail-open path leaked policy/role/subject readers into raw-
 * browser bundles that don't shim `process` and into engines that don't
 * surface `mode`. CWE-200 / CWE-489 — closed by inverting the default.
 *
 * Intentionally has no escape hatch: if you need devtools in a deployed
 * environment, run a dev build behind an admin-only route — do not paper
 * over this check with a prop.
 *
 * @param engine - The runtime engine the panel would inspect.
 * @returns `true` when devtools MAY render, `false` to block.
 */
export function isDevtoolsAllowed(engine: IDevtoolsEngine): boolean {
  // `process` may be undefined in raw-browser bundles that don't shim it.
  // We do not treat "no process" as a development signal — see SEC-021.
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
