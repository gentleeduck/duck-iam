// Cache and in-flight invalidation, kept out of the engine class. Each function takes its caches explicitly.

import type { IamLRUCache } from '../../shared/cache'
import type { AccessControl, IamRequest } from '../types'
import { isThenable } from './engine.hooks'
import type { IamEngineTypes } from './engine.types'

/** Every cache one engine owns, passed explicitly so each function here is testable on its own. */
export interface IEngineCacheBag<TRole extends string = string> {
  policyCache: IamLRUCache<AccessControl.IPolicy[]>
  roleCache: IamLRUCache<AccessControl.IRole[]>
  rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  subjectCache: IamLRUCache<IamRequest.ISubject>
  inFlight: IEngineInFlightBag
  invalidator?: IamEngineTypes.IInvalidator<TRole>
}

/**
 * Publishes to the fleet without letting the transport decide a local call's outcome. The local caches are
 * already cleared by the time this runs, so the only thing at stake is whether peers hear about it.
 * SECURITY: a bare `void publish(...)` left a rejection unhandled, which ends the process under Node's default
 * `--unhandled-rejections=throw`, and a synchronous throw propagated out of a write that had already succeeded -
 * on the revocation path, from code an operator supplies.
 */
function publishQuietly<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  event: IamEngineTypes.IInvalidateEvent<TRole>,
): void {
  try {
    const result = bag.invalidator?.publish(event)
    if (isThenable(result)) result.then(undefined, (err: unknown) => reportPublishFailure(event, err))
  } catch (err) {
    reportPublishFailure(event, err)
  }
}

/** Never silent: every peer that missed the event serves the old answer until its own TTL expires. */
function reportPublishFailure(event: { kind: string }, err: unknown): void {
  try {
    console.warn(
      `[@gentleduck/iam:engine] invalidator.publish(${JSON.stringify(event.kind)}) failed; this instance is ` +
        'up to date but other instances keep their caches until their own TTL expires. ' +
        `(${err instanceof Error ? err.message : String(err)})`,
    )
  } catch {}
}

/**
 * The load in flight for one cache key, or `null`.
 * NOTE: a mutable box, not a bare promise, so the loader and an invalidation clear the same slot.
 */
export interface ISingleFlightSlot<T> {
  value: Promise<T> | null
}

/**
 * The single-flight slot for each cache.
 * WARN: clearing a cache must clear its slot too, or the in-flight load repopulates it with stale data.
 */
export interface IEngineInFlightBag {
  policies: ISingleFlightSlot<AccessControl.IPolicy[]>
  roles: ISingleFlightSlot<AccessControl.IRole[]>
  rbac: ISingleFlightSlot<AccessControl.IPolicy>
  merged: ISingleFlightSlot<AccessControl.IPolicy[]>
  subjects: Map<string, Promise<IamRequest.ISubject>>
}

/**
 * Drops every cache and its in-flight slot.
 * `broadcast: false` applies a received event without republishing it, so two engines never bounce it forever.
 */
export function invalidateAll<TRole extends string>(bag: IEngineCacheBag<TRole>, opts: { broadcast?: boolean }): void {
  bag.policyCache.clear()
  bag.roleCache.clear()
  bag.rbacPolicyCache.clear()
  bag.subjectCache.clear()
  bag.inFlight.policies.value = null
  bag.inFlight.roles.value = null
  bag.inFlight.rbac.value = null
  bag.inFlight.merged.value = null
  bag.mergedPolicyCache.clear()
  bag.inFlight.subjects.clear()
  if (opts.broadcast !== false && bag.invalidator) {
    publishQuietly(bag, { kind: 'all' })
  }
}

/**
 * Drops one subject's resolved roles.
 * NOTE: an unusable `subjectId` is ignored, not thrown: it may come from a peer, and an eviction stays quiet.
 */
export function invalidateSubject<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  subjectId: string,
  opts: { broadcast?: boolean },
): void {
  if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return
  bag.subjectCache.delete(subjectId)
  bag.inFlight.subjects.delete(subjectId)
  if (opts.broadcast !== false && bag.invalidator) {
    publishQuietly(bag, { kind: 'subject', subjectId })
  }
}

/**
 * Drops the policy caches and the merged view.
 * NOTE: merged is derived from policies plus RBAC; clearing policies without it would keep serving the old set.
 */
export function invalidatePolicies<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  opts: { broadcast?: boolean },
): void {
  bag.policyCache.clear()
  bag.inFlight.policies.value = null
  bag.inFlight.merged.value = null
  bag.mergedPolicyCache.clear()
  if (opts.broadcast !== false && bag.invalidator) {
    publishQuietly(bag, { kind: 'policies' })
  }
}

/**
 * Drops the role caches, the RBAC projection and the merged view wholesale, since inheritance can reach anyone.
 * `roleIdInput` only narrows the subject sweep; an unusable id sweeps every subject (see {@link invalidateSubject}).
 */
/**
 * `roleId` plus every cached role whose `inherits` chain reaches it.
 * SECURITY: a closure cached while `roleId` was missing holds only the roles that reach it, so those must drop too.
 */
function rolesReaching(roles: readonly AccessControl.IRole[], roleId: string): Set<string> {
  const inheritors = new Map<string, string[]>()
  for (const role of roles) {
    for (const parent of role.inherits ?? []) {
      const known = inheritors.get(parent)
      if (known) known.push(role.id)
      else inheritors.set(parent, [role.id])
    }
  }
  const reaching = new Set<string>([roleId])
  const queue = [roleId]
  while (queue.length > 0) {
    const current = queue.pop()
    if (current === undefined) continue
    for (const inheritor of inheritors.get(current) ?? []) {
      if (reaching.has(inheritor)) continue
      reaching.add(inheritor)
      queue.push(inheritor)
    }
  }
  return reaching
}

export function invalidateRoles<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  roleIdInput: TRole | undefined,
  opts: { broadcast?: boolean },
): void {
  let roleId = roleIdInput
  if (roleId !== undefined && (typeof roleId !== 'string' || roleId.length === 0 || roleId.length > 1024)) {
    roleId = undefined
  }
  // Read before the clear below: the sweep needs the inheritance edges the cached closures were built from.
  const graph = bag.roleCache.get('all')
  bag.roleCache.clear()
  bag.rbacPolicyCache.clear()
  bag.inFlight.roles.value = null
  bag.inFlight.rbac.value = null
  bag.inFlight.merged.value = null
  bag.mergedPolicyCache.clear()
  // SECURITY: unconditional. An in-flight load has no cache entry for the sweep below to match, and one started
  // before a revoke would cache the old roles for a full TTL.
  bag.inFlight.subjects.clear()
  // SECURITY: saving a role an assigned role inherits adds it to closures cached before it existed, and those
  // closures name only the roles that reach it. With no cached graph to name them, every subject goes.
  if (roleId === undefined || graph === undefined) {
    bag.subjectCache.clear()
  } else {
    const affected = rolesReaching(graph, roleId)
    for (const [subjectId, subject] of bag.subjectCache.entries()) {
      const inRoles = subject.roles.some((role) => affected.has(role))
      const inScoped = subject.scopedRoles?.some((sr) => affected.has(sr.role)) ?? false
      if (inRoles || inScoped) bag.subjectCache.delete(subjectId)
    }
  }
  if (opts.broadcast !== false && bag.invalidator) {
    publishQuietly(bag, { kind: 'roles', roleId })
  }
}

/** Per-kind shape check for an inbound event: `subjectId` required, `roleId` optional, neither empty. */
function isApplicableEvent<TRole extends string>(ev: unknown): ev is IamEngineTypes.IInvalidateEvent<TRole> {
  if (typeof ev !== 'object' || ev === null || Array.isArray(ev)) return false
  const kind = Reflect.get(ev, 'kind')
  if (kind === 'all' || kind === 'policies') return true
  if (kind === 'roles') {
    const roleId = Reflect.get(ev, 'roleId')
    return roleId === undefined || (typeof roleId === 'string' && roleId.length > 0)
  }
  if (kind === 'subject') {
    const subjectId = Reflect.get(ev, 'subjectId')
    return typeof subjectId === 'string' && subjectId.length > 0
  }
  return false
}

/** An inbound value classified once: either an event this engine can apply, or the reason it cannot. */
type IInboundEvent<TRole extends string> =
  | { readonly ok: true; readonly event: IamEngineTypes.IInvalidateEvent<TRole> }
  | { readonly ok: false; readonly reason: string }

/**
 * Classifies an inbound value. Total by construction: the value crossed a transport an operator supplies, so a
 * hostile getter or a revoked proxy has to come back as a reason rather than as a throw into that transport.
 */
function classifyInbound<TRole extends string>(ev: unknown): IInboundEvent<TRole> {
  try {
    if (isApplicableEvent<TRole>(ev)) return { event: ev, ok: true }
    return { ok: false, reason: unapplicableReason(ev) }
  } catch (err) {
    return { ok: false, reason: `could not be read (${err instanceof Error ? err.message : String(err)})` }
  }
}

/** Names why an event that failed {@link isApplicableEvent} failed it, for the warning. */
function unapplicableReason(ev: unknown): string {
  if (typeof ev !== 'object' || ev === null || Array.isArray(ev)) {
    return `not an event object (${ev === null ? 'null' : Array.isArray(ev) ? 'array' : typeof ev})`
  }
  const kind = Reflect.get(ev, 'kind')
  if (kind === 'roles' || kind === 'subject') return `kind ${JSON.stringify(kind)} with an unusable id`
  return `unrecognised kind ${JSON.stringify(kind)}`
}

const reportedInboundReasons = new Set<string>()

/**
 * Fail closed: something changed that this engine cannot place, so it drops everything rather than guess.
 * Local only, so a peer that sends nonsense cannot amplify it across the fleet.
 */
function reportUnapplicableEvent(reason: string): void {
  if (reportedInboundReasons.has(reason)) return
  reportedInboundReasons.add(reason)
  try {
    console.warn(
      `[@gentleduck/iam:engine] invalidator delivered an event this engine cannot apply: ${reason}. ` +
        'Every local cache was dropped rather than serve an answer the sender says is stale. ' +
        'Reported once per distinct reason.',
    )
  } catch {}
}

/**
 * Applies an invalidation received from another engine instance, and returns the kind it actually applied.
 * The value crossed a transport an operator supplies, so it is checked here rather than trusted from its type.
 * NOTE: every branch passes `broadcast: false`; echoing peers' events would grow traffic with the fleet squared.
 */
export function applyInvalidateEvent<TRole extends string>(
  bag: IEngineCacheBag<TRole>,
  event: unknown,
): IamEngineTypes.IInvalidateEvent<TRole>['kind'] {
  const inbound = classifyInbound<TRole>(event)
  if (!inbound.ok) {
    reportUnapplicableEvent(inbound.reason)
    invalidateAll(bag, { broadcast: false })
    return 'all'
  }
  switch (inbound.event.kind) {
    case 'all':
      invalidateAll(bag, { broadcast: false })
      return 'all'
    case 'policies':
      invalidatePolicies(bag, { broadcast: false })
      return 'policies'
    case 'roles':
      invalidateRoles(bag, inbound.event.roleId, { broadcast: false })
      return 'roles'
    case 'subject':
      invalidateSubject(bag, inbound.event.subjectId, { broadcast: false })
      return 'subject'
  }
}

/** @internal Test seam: the once-per-reason warning is process-wide. */
export function _resetInboundEventReports(): void {
  reportedInboundReasons.clear()
}
