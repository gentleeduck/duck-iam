import { iamBuildPermissionKey, iamParsePermissionKey } from './keys'

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
 * Whether `map` grants `action` on `resource` (optionally one instance, within a scope).
 * Every client binding's `can()` is {@link iamBuildPermissionKey} then {@link iamPermissionGranted}; this is that pair.
 *
 * @param map - Permission map to check.
 * @param action - Action to check.
 * @param resource - Resource type to check.
 * @param resourceId - Optional specific instance.
 * @param scope - Optional scope the grant is confined to.
 */
export function iamCan(map: object, action: string, resource: string, resourceId?: string, scope?: string): boolean {
  return iamPermissionGranted(map, iamBuildPermissionKey(action, resource, resourceId, scope))
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
