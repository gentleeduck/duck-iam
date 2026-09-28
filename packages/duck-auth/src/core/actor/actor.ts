import { AsyncLocalStorage } from 'node:async_hooks'
import type { Actor } from './actor.types'

const _als = new AsyncLocalStorage<string | undefined>()
let _default: Actor.Resolver | undefined

/** Binds `actorId` for `fn`, across awaits. An id naming nobody - `undefined` or `''` - clears the scope. */
export function withActor<T>(actorId: string | undefined, fn: () => T): T {
  return _als.run(actorId || undefined, fn)
}

/** Installs the process-wide fallback; `undefined` clears it. */
export function setDefaultActorResolver(resolve: Actor.Resolver | undefined): void {
  _default = resolve
}

/** The scope's actor, then the configured default, then `null`.
 *  WARN: a resolver that throws is not caught - a broken actor lookup is a wiring bug, not a `null`. */
export function actorId(): string | null {
  return _als.getStore() || _default?.() || null
}
