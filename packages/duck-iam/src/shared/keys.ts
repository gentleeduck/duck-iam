/**
 * Marks the leading segment as a scope. A scoped key is the only one that may
 * start with an unescaped `@`, which is what makes the arity unambiguous.
 */
const SCOPE_PREFIX = '@'

/**
 * Permission map key `[@scope:]action:resource[:resourceId]`, with `:`, `\` and a leading `@` backslash-escaped.
 * NOTE: the `@` marker keeps `('read', 'doc', '42')` and `('doc', '42', undefined, 'read')` from sharing a key.
 */
export function iamBuildPermissionKey(action: string, resource: string, resourceId?: string, scope?: string): string {
  const e = escapeSegment
  const tail = resourceId !== undefined ? `${e(action)}:${e(resource)}:${e(resourceId)}` : `${e(action)}:${e(resource)}`
  // `!== undefined`, not truthiness: an empty scope or resourceId is a distinct segment, not the shorter key.
  return scope !== undefined ? `${SCOPE_PREFIX}${e(scope)}:${tail}` : tail
}

/**
 * Reverse of {@link iamBuildPermissionKey}. Returns `null` for a string that is not a well-formed key, so a hand-built
 * one is rejected rather than guessed at.
 */
export function iamParsePermissionKey(key: string): {
  scope: string | undefined
  action: string
  resource: string
  resourceId: string | undefined
} | null {
  // Read the marker off the raw key: the splitter unescapes, and a literal
  // leading `@` inside a segment is escaped, so this test cannot misfire.
  const scoped = key.startsWith(SCOPE_PREFIX)
  const parts = iamSplitPermissionKey(scoped ? key.slice(SCOPE_PREFIX.length) : key)
  const expected = scoped ? [3, 4] : [2, 3]
  if (!expected.includes(parts.length)) return null
  const scope = scoped ? parts.shift() : undefined
  const [action, resource, resourceId] = parts
  if (action === undefined || resource === undefined) return null

  // NOTE: well-formed means the builder emits exactly this key. A merely splittable key would let
  // `allowedActions()` / `hasAnyOn()` report a grant that `can()` misses.
  if (iamBuildPermissionKey(action, resource, resourceId, scope) !== key) return null

  return { action, resource, resourceId, scope }
}

function escapeSegment(s: string): string {
  const escaped = s.includes(':') || s.includes('\\') ? s.replace(/\\/g, '\\\\').replace(/:/g, '\\:') : s
  // Only a leading `@` needs escaping: it is the scope marker, and a segment
  // that could pose as one would reintroduce the arity ambiguity.
  return escaped.startsWith(SCOPE_PREFIX) ? `\\${escaped}` : escaped
}

/**
 * Splits a key from {@link iamBuildPermissionKey} into unescaped segments, honouring `\:`, `\\` and `\@`.
 * A scoped key's leading `@` is not stripped; use {@link iamParsePermissionKey} for that.
 *
 * @param key - Permission key, e.g. `'read:document'` or `'write:doc\\:42'`.
 */
export function iamSplitPermissionKey(key: string): string[] {
  const out: string[] = []
  let current = ''
  let i = 0
  while (i < key.length) {
    const ch = key[i]
    if (ch === undefined) break
    // Only the three escapes are recognised, so a crafted `\x` stays literal. Past the end `next` is `undefined`.
    const next = key[i + 1]
    if (ch === '\\' && (next === ':' || next === '\\' || next === SCOPE_PREFIX)) {
      current += next
      i += 2
      continue
    }
    if (ch === ':') {
      out.push(current)
      current = ''
      i++
      continue
    }
    current += ch
    i++
  }
  out.push(current)
  return out
}
