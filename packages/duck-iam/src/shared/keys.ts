/**
 * Marks the leading segment as a scope. A scoped key is the only one that may
 * start with an unescaped `@`, which is what makes the arity unambiguous.
 */
const SCOPE_PREFIX = '@'

/**
 * Permission map key: `[@scope:]action:resource[:resourceId]`. Inside a segment
 * `:` and `\` are backslash-escaped, and a leading `@` is escaped too.
 *
 * The `@` on the scope is what disambiguates a three-segment key. Without it
 * `('read', 'doc', '42')` and `('doc', '42', undefined, 'read')` both produced
 * `read:doc:42`, so two different checks in one `checkMany` shared a map entry
 * and one could answer for the other.
 *
 * @param action - Identifies the action (for example `'read'`).
 * @param resource - Identifies the resource (for example `'document'`).
 * @param resourceId - Optionally pins the key to a concrete resource instance.
 * @param scope - Optionally prefixes a scope for tenant or namespace partitioning.
 * @returns Composed colon-delimited key with hostile segments escaped.
 */
export function iamBuildPermissionKey(action: string, resource: string, resourceId?: string, scope?: string): string {
  const e = escapeSegment
  const tail = resourceId !== undefined ? `${e(action)}:${e(resource)}:${e(resourceId)}` : `${e(action)}:${e(resource)}`
  // `!== undefined`, not truthiness: an empty-string scope or resourceId is a
  // distinct segment, otherwise it silently collides with the unscoped key.
  return scope !== undefined ? `${SCOPE_PREFIX}${e(scope)}:${tail}` : tail
}

/**
 * Reverse of {@link iamBuildPermissionKey}. Returns `null` for a string that is
 * not a well-formed key, so a hand-built one is rejected rather than guessed at.
 *
 * @param key - Permission key to parse.
 * @returns The original fields, or `null` when `key` is not in this format.
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
  return { action, resource, resourceId, scope }
}

function escapeSegment(s: string): string {
  const escaped = s.includes(':') || s.includes('\\') ? s.replace(/\\/g, '\\\\').replace(/:/g, '\\:') : s
  // Only a leading `@` needs escaping: it is the scope marker, and a segment
  // that could pose as one would reintroduce the arity ambiguity.
  return escaped.startsWith(SCOPE_PREFIX) ? `\\${escaped}` : escaped
}

/**
 * Splits a permission key produced by {@link iamBuildPermissionKey} into its
 * original segments, honouring the `\:`, `\\` and `\@` escape sequences. Naive
 * `.split(':')` would mis-tokenise any segment containing a literal `:` or
 * `\`. The leading `@` of a scoped key is not a segment and is not stripped
 * here; use {@link iamParsePermissionKey} for that.
 *
 * @param key - Permission key, e.g. `'read:document'` or `'write:doc\\:42'`.
 * @returns Array of unescaped segments in declaration order.
 */
export function iamSplitPermissionKey(key: string): string[] {
  const out: string[] = []
  let current = ''
  let i = 0
  while (i < key.length) {
    const ch = key[i] as string
    if (ch === '\\' && i + 1 < key.length) {
      const next = key[i + 1] as string
      // Only the three escape sequences are recognised; anything else is
      // treated literally so an attacker-crafted `\x` doesn't silently
      // become `x`.
      if (next === ':' || next === '\\' || next === SCOPE_PREFIX) {
        current += next
        i += 2
        continue
      }
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
