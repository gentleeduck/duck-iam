import { iamParsePermissionKey } from './keys'

/**
 * Reads one grant out of a client permission map.
 * SECURITY: the map is unvalidated server JSON, so only a literal `true` grants; truthiness would accept `"false"`.
 *
 * @param map - The permission map to read.
 * @param key - A key built by `iamBuildPermissionKey`.
 * @returns `true` only when the map has its own `key` set to boolean `true`.
 */
export function iamPermissionGranted(map: object, key: string): boolean {
  if (!Object.hasOwn(map, key)) return false
  return Reflect.get(map, key) === true
}

/**
 * Lists every action granted on `resource` by a client permission map.
 * NOTE: returns `string[]`, not the action union, because the map is unvalidated; narrow with your own predicate.
 *
 * @param map - Permission map as received from the server.
 * @param resource - Resource type to filter by.
 * @returns Deduplicated actions granted on `resource`.
 */
export function iamAllowedActions(map: object, resource: string): string[] {
  const actions: string[] = []
  for (const [key, allowed] of Object.entries(map)) {
    const action = grantedActionForResource(key, allowed, resource)
    // `!== null`, not truthiness: an empty-string action is a real segment that `can()` honours.
    if (action !== null) actions.push(action)
  }
  return [...new Set(actions)]
}

/**
 * Returns whether the map grants at least one action on `resource`.
 *
 * @param map - Permission map as received from the server.
 * @param resource - Resource type to probe.
 * @returns `true` when any granted key targets `resource`.
 */
export function iamHasAnyOn(map: object, resource: string): boolean {
  return Object.entries(map).some(([key, allowed]) => grantedActionForResource(key, allowed, resource) !== null)
}

/**
 * The action `key` grants on `resource`, or `null` when `allowed` is not a literal `true`, `key` targets something
 * else, or `key` is not one this package built. Shared by {@link iamAllowedActions} and {@link iamHasAnyOn}, which
 * differ only in collecting every match versus stopping at the first.
 * SECURITY: `allowed === true`, matching `iamPermissionGranted`: a truthiness test would grant on the string "false".
 */
function grantedActionForResource(key: string, allowed: unknown, resource: string): string | null {
  if (allowed !== true) return null
  const parsed = iamParsePermissionKey(key)
  if (parsed === null || parsed.resource !== resource) return null
  return parsed.action
}
