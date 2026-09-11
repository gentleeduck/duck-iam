import type { AccessControl } from '../../core/types'
import type { IamIDevtoolsEngine } from './types'

/**
 * Production guard for the devtools: `true` only on an explicit development signal from `NODE_ENV` or the engine.
 * SECURITY: fails closed - `production` on either side, or no signal at all, blocks. No escape hatch (CWE-200/489).
 */
export function isDevtoolsAllowed(engine: IamIDevtoolsEngine): boolean {
  const nodeEnv = readNodeEnv()

  // SECURITY: a production signal on either side wins. The subjects panel calls
  // `assignRole`/`revokeRole`/`setAttributes` with no auth of its own.
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
 * `NODE_ENV` when readable, else `undefined`.
 * NOTE: `process` may be missing or oddly shimmed in browser bundles; both count as no development signal.
 */
function readNodeEnv(): string | undefined {
  if (typeof process === 'undefined') return undefined
  const env: unknown = Reflect.get(process, 'env')
  if (typeof env !== 'object' || env === null) return undefined
  const value: unknown = Reflect.get(env, 'NODE_ENV')
  return typeof value === 'string' ? value : undefined
}

/**
 * The engine mode from `mode`, `config.mode`, or the real engine's TS-private `_mode`, in that order.
 * SECURITY: plain `??`, not first-valid-wins, so an unrecognised `mode` is never overridden by a later `_mode`.
 */
function readEngineMode(engine: IamIDevtoolsEngine): AccessControl.Mode | undefined {
  const config: unknown = Reflect.get(engine, 'config')
  const nested: unknown = typeof config === 'object' && config !== null ? Reflect.get(config, 'mode') : undefined
  const raw: unknown = Reflect.get(engine, 'mode') ?? nested ?? Reflect.get(engine, '_mode')
  if (raw === 'production' || raw === 'development') return raw
  return undefined
}
