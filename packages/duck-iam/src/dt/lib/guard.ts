import type { AccessControl } from '../../core/types'
import type { IamIDevtoolsEngine } from './types'

/**
 * Hard production guard for the IAM devtools - default-block.
 *
 * Returns `true` ONLY when an explicit positive `development` signal is
 * present - either the bundler set `NODE_ENV=development` or the engine was
 * constructed in `'development'` mode - and neither side reports
 * `production`, which blocks unconditionally. Absence of any signal blocks the
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
export function isDevtoolsAllowed(engine: IamIDevtoolsEngine): boolean {
  const nodeEnv = readNodeEnv()

  // Either production signal blocks, and blocking wins. The panel is not
  // read-only - `IamIDevtoolsEngine` requires `assignRole` / `revokeRole` /
  // `setAttributes` and the subjects panel calls all three with no auth of its
  // own - so a staging box left on NODE_ENV=development in front of a
  // production-mode engine must not mount it.
  if (nodeEnv === 'production') return false
  const mode = readEngineMode(engine)
  if (mode === 'production') return false

  // Positive development signals - either side is sufficient.
  if (nodeEnv === 'development') return true
  if (mode === 'development') return true

  // No positive signal -> BLOCK.
  return false
}

/**
 * `NODE_ENV`, or undefined when there is nothing to read.
 *
 * `process` may be undefined in raw-browser bundles that don't shim it, and a
 * shim may define it as something other than an object with a string
 * `NODE_ENV`. "No process" and "a process whose env says something unreadable"
 * are both the absence of a development signal, which blocks.
 */
function readNodeEnv(): string | undefined {
  if (typeof process === 'undefined') return undefined
  const env: unknown = Reflect.get(process, 'env')
  if (typeof env !== 'object' || env === null) return undefined
  const value: unknown = Reflect.get(env, 'NODE_ENV')
  return typeof value === 'string' ? value : undefined
}

/**
 * The engine's own mode, read by name across the three shapes engines have
 * carried it under.
 *
 * `_mode` is a TypeScript-`private` field on the real engine, which means it is
 * a plain own property at runtime and this is the only way to see it. Read
 * positionally with `??` rather than "first valid wins": an engine reporting
 * `mode: 'staging'` must not have that ignored in favour of a `_mode` further
 * down, because an unreadable mode is itself a reason to block.
 */
function readEngineMode(engine: IamIDevtoolsEngine): AccessControl.Mode | undefined {
  const config: unknown = Reflect.get(engine, 'config')
  const nested: unknown = typeof config === 'object' && config !== null ? Reflect.get(config, 'mode') : undefined
  const raw: unknown = Reflect.get(engine, 'mode') ?? nested ?? Reflect.get(engine, '_mode')
  if (raw === 'production' || raw === 'development') return raw
  return undefined
}
