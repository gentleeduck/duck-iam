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
    // `=== true`, matching `iamPermissionGranted`: a truthiness test lists an
    // action whose value is the string "false".
    if (allowed !== true) continue
    const action = iamActionForResource(key, resource)
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
  return Object.entries(map).some(([key, allowed]) => {
    if (allowed !== true) return false
    return iamActionForResource(key, resource) !== null
  })
}

/**
 * Extracts the action from a permission key for a given resource, or `null`
 * when the key targets something else or is not a key this package built.
 */
function iamActionForResource(key: string, resource: string): string | null {
  const parsed = iamParsePermissionKey(key)
  if (parsed === null || parsed.resource !== resource) return null
  return parsed.action
}
