/** Per-request actor scope via AsyncLocalStorage. Mirrors `~/core/tenant`. */

import { AsyncLocalStorage } from 'node:async_hooks'
import type { ActorContext } from './actor.types'

const _als = new AsyncLocalStorage<ActorContext>()

/** Run `fn` with `actorId` bound; `currentActor()` resolves to it across awaits. */
export function withActor<T>(actorId: string | undefined, fn: () => T | Promise<T>): T | Promise<T> {
  return _als.run(actorId !== undefined ? { actorId } : {}, fn)
}

/** Read the current actor scope; prefer {@link resolveActor} for caller-supplied overrides. */
export function currentActor(): ActorContext | undefined {
  return _als.getStore()
}

/**
 * Pick the effective actor for one write. An explicit actor wins over the
 * ambient, so a single call can be attributed to someone other than whoever
 * the request is bound to - an operator acting on a user's row, say.
 * `withActor` is a default, not a fence.
 */
export function resolveActor(explicit?: ActorContext): ActorContext {
  if (explicit?.actorId !== undefined) return explicit
  return _als.getStore() ?? {}
}

/**
 * Process-wide last-resort resolver, set from `AuthEngine`'s `resolveActor`
 * config or directly by {@link setDefaultActorResolver}.
 *
 * Module-level on purpose: it exists so a consumer whose framework already has
 * a request context - a NestJS request-scoped provider, a Hono context getter -
 * can wire it once instead of wrapping every handler in `withActor`. Ambient
 * scope still wins, so a `withActor` around a specific call is never overridden
 * by it.
 */
let _default: (() => string | null | undefined) | undefined

/**
 * Install the fallback used when no actor is bound. Passing `undefined` clears
 * it. The last caller wins, so in a process running more than one engine this
 * is shared state - bind per request with {@link withActor} there instead.
 */
export function setDefaultActorResolver(resolve: (() => string | null | undefined) | undefined): void {
  _default = resolve
}

/**
 * The id to stamp on a write: explicit, then ambient, then the configured
 * default, then `null`. A resolver that throws is not caught - a broken actor
 * lookup is a bug in the consumer's wiring, and swallowing it would put the
 * NULL provenance back that this whole mechanism exists to remove.
 */
export function actorId(explicit?: ActorContext): string | null {
  const resolved = resolveActor(explicit).actorId
  if (resolved !== undefined) return resolved
  return _default?.() ?? null
}
