import { AsyncLocalStorage } from 'node:async_hooks'
import type { Actor } from './actor.types'

const _als = new AsyncLocalStorage<Actor.Context>()
let _default: Actor.Resolver | undefined

/** Binds `actorId` for `fn`, across awaits. An id naming nobody - `undefined` or `''` - clears the scope. */
export function withActor<T>(actorId: string | undefined, fn: () => T): T {
  return _als.run(actorId ? { actorId } : {}, fn)
}

/** The scope in force, `undefined` outside one; prefer {@link resolveActor} for caller-supplied overrides. */
export function currentActor(): Actor.Context | undefined {
  return _als.getStore()
}

/** `explicit` when it names an actor, else the ambient scope. */
export function resolveActor(explicit?: Actor.Context): Actor.Context {
  if (explicit?.actorId) return explicit
  return _als.getStore() ?? {}
}

/** Installs the process-wide fallback; `undefined` clears it. */
export function setDefaultActorResolver(resolve: Actor.Resolver | undefined): void {
  _default = resolve
}

/** Explicit, then ambient, then the configured default, then `null`.
 *  WARN: a resolver that throws is not caught - a broken actor lookup is a wiring bug, not a `null`. */
export function actorId(explicit?: Actor.Context): string | null {
  return resolveActor(explicit).actorId || _default?.() || null
}
