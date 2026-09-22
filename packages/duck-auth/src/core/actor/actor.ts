/** Mirrors `~/core/tenant`, over the same AsyncLocalStorage mechanism. */

import { AsyncLocalStorage } from 'node:async_hooks'
import type { ActorContext } from './actor.types'

const _als = new AsyncLocalStorage<ActorContext>()

/** Binds `actorId` for `fn`, across awaits. */
export function withActor<T>(actorId: string | undefined, fn: () => T | Promise<T>): T | Promise<T> {
  return _als.run(actorId !== undefined ? { actorId } : {}, fn)
}

/** Read the current actor scope; prefer {@link resolveActor} for caller-supplied overrides. */
export function currentActor(): ActorContext | undefined {
  return _als.getStore()
}

/** An explicit actor beats the ambient one, so one write can be attributed to someone other than the
 *  request's own actor, an operator touching a user's row say: {@link withActor} is a default, not a fence. */
export function resolveActor(explicit?: ActorContext): ActorContext {
  if (explicit?.actorId !== undefined) return explicit
  return _als.getStore() ?? {}
}

/** Module-level on purpose, so a consumer whose framework already carries a request context wires it once
 *  rather than wrapping every handler. Ambient scope still beats it. */
let _default: (() => string | null | undefined) | undefined

/** `undefined` clears it. The last caller wins, so this is shared state in a process running more than
 *  one engine; bind per request with {@link withActor} there instead. */
export function setDefaultActorResolver(resolve: (() => string | null | undefined) | undefined): void {
  _default = resolve
}

/**
 * Explicit, then ambient, then the configured default, then `null`.
 *
 * WARN: a resolver that throws is not caught. A broken actor lookup is a wiring bug, and swallowing it
 * would restore the NULL provenance this mechanism exists to remove.
 */
export function actorId(explicit?: ActorContext): string | null {
  const resolved = resolveActor(explicit).actorId
  if (resolved !== undefined) return resolved
  return _default?.() ?? null
}
