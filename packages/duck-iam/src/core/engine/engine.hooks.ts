/**
 * Hook fire-and-forget helpers. Both wrap user-provided callbacks so a
 * throw never escapes the call site. `console.error` itself can throw
 * (closed stdout in a daemon, a broken pipe, a buggy user-replaced
 * Console), so the diagnostic write is also wrapped.
 */

import type { AccessControl, IamRequest } from '../types'
import type { IamEngineTypes } from './engine.types'

/**
 * Run a user hook and swallow anything it throws.
 *
 * A hook is an observer, never a participant: the decision is already made by
 * the time one runs, so a throwing `onDeny` must not turn a decided request
 * into an error. The name is passed in only so the swallowed throw can say
 * which hook produced it.
 *
 * @param fn       - The user callback to invoke.
 * @param hookName - Name used in the diagnostic when `fn` throws.
 */
export async function safeHookCall(fn: () => unknown, hookName: string): Promise<void> {
  try {
    await fn()
  } catch (err) {
    try {
      console.error(`[@gentleduck/iam:engine] ${hookName} hook threw - swallowed to preserve decision`, err)
    } catch {
      /* last-resort: give up logging; decision is more important than diagnostics */
    }
  }
}

/**
 * Hand one evaluation's timing and outcome to the `onMetrics` hook, if any.
 *
 * `failOpen` is reported separately from `allowed` because the two mean very
 * different things to an operator: an allow the policies produced and an allow
 * the engine produced because its adapter was unreachable must never be read
 * off the same counter.
 *
 * @param hooks    - The configured hook bag; a missing `onMetrics` is a no-op.
 * @param req      - The request that was evaluated.
 * @param allowed  - The verdict handed to the caller.
 * @param t0       - `performance.now()` sampled before evaluation began.
 * @param failOpen - Whether that verdict came from the fail-open path.
 * @param mode     - Engine mode, so a consumer can tell dev traffic apart.
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
