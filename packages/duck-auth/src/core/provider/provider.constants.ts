import type { Identities } from '../identities'
import type { Provider } from './provider.types'

/**
 * The shape an id may have. A provider id is chosen by config and then quoted back in errors, put in
 * a route segment and written to a log line, so the set is what survives all three unescaped.
 */
const PROVIDER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/
const PROVIDER_ID_MAX_LENGTH = 128

/** Ids that would land on `Object.prototype` in a caller's own `{}` keyed by provider id. */
const RESERVED_PROVIDER_IDS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype'])

function isUsableId(id: unknown): id is string {
  if (typeof id !== 'string') return false
  if (id.length === 0 || id.length > PROVIDER_ID_MAX_LENGTH) return false
  if (RESERVED_PROVIDER_IDS.has(id.toLowerCase())) return false
  return PROVIDER_ID_PATTERN.test(id)
}

/**
 * The key a capability is registered and looked up under, or null when the string cannot be one.
 *
 * Case-folded, so a provider id that reaches the registry from a request body resolves the same
 * capability whatever case it arrived in.
 */
export function canonicalProviderId(id: unknown): string | null {
  return isUsableId(id) ? id.toLowerCase() : null
}

/** The id as it may be quoted back to a caller. Anything else is caller-chosen text in a response body. */
export function echoableProviderId(id: unknown): string {
  return isUsableId(id) ? id : 'invalid'
}

/** A capability that exposes begin/complete is a sign-in provider. */
export function isSignInCapability<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  cap: Provider.Capability,
): cap is Provider.Me<unknown, unknown, Profile> {
  return typeof cap.begin === 'function' && typeof cap.complete === 'function'
}

/**
 * A plain object with neither begin nor complete can never be dispatched and can never answer
 * `resolve`, so registering it makes it look wired while nothing can reach it. That is exactly what
 * `{ ...facet }` produces: the spread keeps the fields and drops the prototype the methods were on.
 */
export function isUnreachableCapability(cap: Provider.Capability): boolean {
  const proto: unknown = Object.getPrototypeOf(cap)
  return (proto === Object.prototype || proto === null) && !isSignInCapability(cap)
}

/**
 * How a refused id is named back to whoever wrote the config. JSON-quoted, so an id that carries a
 * quote or a control character cannot end the sentence it is being reported in.
 */
export function describeProviderId(id: unknown): string {
  return typeof id === 'string' ? JSON.stringify(id.slice(0, PROVIDER_ID_MAX_LENGTH)) : String(id)
}
