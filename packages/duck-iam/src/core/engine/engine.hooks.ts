/**
 * Hook fire-and-forget helpers. Both wrap user-provided callbacks so a
 * throw never escapes the call site. `console.error` itself can throw
 * (closed stdout in a daemon, a broken pipe, a buggy user-replaced
 * Console), so the diagnostic write is also wrapped.
 */

import type { AccessControl, Request } from '../types'
import type { EngineTypes } from './engine.types'

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

export function emitMetrics<TAction extends string, TResource extends string, TScope extends string>(
  hooks: EngineTypes.IHooks<TAction, TResource, TScope>,
  req: Request.IAccessRequest<TAction, TResource, TScope>,
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
