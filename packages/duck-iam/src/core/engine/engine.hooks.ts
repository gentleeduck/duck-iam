// Hook helpers: a user callback's throw never escapes the call site. `console.error` can throw too
// (closed stdout, broken pipe), so the diagnostic write is wrapped as well.

import type { AccessControl, IamRequest } from '../types'
import type { IamEngineTypes } from './engine.types'

/** True for anything `await` treats as a promise. Reading `then` can throw, so call it inside a `try`. */
export function isThenable(value: unknown): value is PromiseLike<unknown> {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) return false
  return typeof Reflect.get(value, 'then') === 'function'
}

/** `IConfig.hookTimeoutMs` when unset. */
export const DEFAULT_HOOK_TIMEOUT_MS = 5_000

/**
 * Runs a user hook and swallows any throw: the decision is already made, and a hook must not turn it into an error.
 * A returned promise is awaited for at most `timeoutMs` (`0` waits indefinitely); a sync return is not timed.
 */
export async function safeHookCall(fn: () => unknown, hookName: string, timeoutMs = 0): Promise<void> {
  let pending: PromiseLike<unknown>
  try {
    const returned = fn()
    if (!isThenable(returned)) return
    pending = returned
  } catch (err) {
    logHookThrow(hookName, err)
    return
  }
  const settled = Promise.resolve(pending).then(
    () => true,
    (err: unknown) => {
      logHookThrow(hookName, err)
      return true
    },
  )
  if (timeoutMs <= 0) {
    await settled
    return
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  const expired = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs)
  })
  const inTime = await Promise.race([settled, expired])
  clearTimeout(timer)
  if (!inTime) logHookTimeout(hookName, timeoutMs)
}

function logHookThrow(hookName: string, err: unknown): void {
  try {
    console.error(`[@gentleduck/iam:engine] ${hookName} hook threw - swallowed to preserve decision`, err)
  } catch {
    /* last-resort: give up logging; decision is more important than diagnostics */
  }
}

function logHookTimeout(hookName: string, timeoutMs: number): void {
  try {
    console.error(
      `[@gentleduck/iam:engine] ${hookName} hook did not settle within ${timeoutMs}ms (hookTimeoutMs) - ` +
        'stopped waiting for it; the call it belongs to has continued and the hook is still running',
    )
  } catch {
    /* last-resort: give up logging */
  }
}

/**
 * Reports one evaluation to `onMetrics`, if set; `t0` is `performance.now()` from before evaluation began.
 * NOTE: `failOpen` is separate from `allowed` so an allow from an unreachable adapter is never read as a policy allow.
 */
export function emitMetrics<TAction extends string, TResource extends string, TScope extends string>(
  hooks: IamEngineTypes.IHooks<TAction, TResource, TScope>,
  req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
  allowed: boolean,
  t0: number,
  failOpen: boolean,
  mode: AccessControl.Mode,
): void {
  const hook = hooks.onMetrics
  if (!hook) return
  try {
    hook({
      subjectId: req.subject.id,
      action: req.action,
      resource: req.resource.type,
      allowed,
      durationMs: performance.now() - t0,
      mode,
      failOpen,
    })
  } catch (err) {
    try {
      console.error('[@gentleduck/iam:engine] onMetrics hook threw - swallowed to preserve decision', err)
    } catch {
      /* last-resort: give up logging */
    }
  }
}
