import { iamParsePermissionKey } from './keys'

/**
 * Reads one grant out of a client permission map.
 *
 * The map arrives from the server as parsed JSON and nothing validates it, so
 * a value is only a grant when it is literally `true`. A truthiness test (or
 * the `as Record<string, boolean>` cast this replaces) reads `"false"` - a
 * plausible thing for a server to emit - as a grant.
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
 *
 * Lived on `IamAccessClient` only, so a React or Vue consumer who needed
 * "what can this user do here" wrote it by hand - and the obvious hand-rolled
 * version is `key.split(':')`, which the `@`-scope marker and the `\:` escaping
 * make wrong on exactly the keys that carry a scope or an id.
 *
 * Returns `string[]`, not the caller's action union. The map is unvalidated
 * server JSON: the union is a claim about what the server *should* have sent,
 * and re-asserting it over parsed keys is the kind of unchecked narrowing that
 * hides a malformed map instead of surfacing it. Narrow with your own predicate
 * if you need the union back.
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
    // `!== null`, not truthiness: an empty-string action is a real segment that
    // `can()` honours, and `iamActionForResource` already signals "not a key
    // here" with `null`.
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
