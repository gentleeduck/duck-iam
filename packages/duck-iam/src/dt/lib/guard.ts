import type { AccessControl } from '../../core/types'
import type { IDevtoolsEngine } from './types'

/**
 * Hard production guard for the IAM devtools. Returns `true` when the panel
 * must NOT mount — either the bundler set `NODE_ENV=production` or the engine
 * was constructed in `'production'` mode.
 *
 * Intentionally has no escape hatch: shipping policy/role/subject readers into
 * a production bundle is a CWE-200 exposure, not a developer-ergonomics knob.
 * If you need devtools in a deployed environment, run a dev build behind an
 * admin-only route — do not paper over this check with a prop.
 */
export function isDevtoolsBlocked(engine: IDevtoolsEngine): boolean {
  // `process` may be undefined in raw-browser bundles that don't shim it. We
  // treat "no process" as non-production for the env-var arm and fall through
  // to the engine-mode arm.
  const nodeEnv: string | undefined =
    typeof process !== 'undefined' ? (process as { env?: { NODE_ENV?: string } }).env?.NODE_ENV : undefined
  if (nodeEnv === 'production') return true

  // The runtime engine carries its mode in `_mode` (private) and re-exposes it
  // through metrics events. We read whichever public-ish shape is present and
  // fall back to safe `false` (i.e., don't block) only when the engine
  // genuinely doesn't advertise a mode.
  const mode = readEngineMode(engine)
  return mode === 'production'
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
