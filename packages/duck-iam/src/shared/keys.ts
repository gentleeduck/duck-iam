/**
 * Permission map key: `[scope:]action:resource[:resourceId]`; `:` and `\` are backslash-escaped per segment.
 *
 * @param action - Identifies the action (for example `'read'`).
 * @param resource - Identifies the resource (for example `'document'`).
 * @param resourceId - Optionally pins the key to a concrete resource instance.
 * @param scope - Optionally prefixes a scope for tenant or namespace partitioning.
 * @returns Composed colon-delimited key with hostile segments escaped.
 */
export function iamBuildPermissionKey(action: string, resource: string, resourceId?: string, scope?: string): string {
  const e = escapeSegment
  // `!== undefined`, not truthiness: an empty-string scope or resourceId is a
  // distinct segment, otherwise it silently collides with the unscoped key.
  if (scope !== undefined) {
    return resourceId !== undefined
      ? `${e(scope)}:${e(action)}:${e(resource)}:${e(resourceId)}`
      : `${e(scope)}:${e(action)}:${e(resource)}`
  }
  return resourceId !== undefined ? `${e(action)}:${e(resource)}:${e(resourceId)}` : `${e(action)}:${e(resource)}`
}

function escapeSegment(s: string): string {
  if (!s.includes(':') && !s.includes('\\')) return s
  return s.replace(/\\/g, '\\\\').replace(/:/g, '\\:')
}

/**
 * Splits a permission key produced by {@link iamBuildPermissionKey} into its
 * original segments, honouring the `\:` and `\\` escape sequences. Naive
 * `.split(':')` would mis-tokenise any segment containing a literal `:` or
 * `\`.
 *
 * @param key - Permission key, e.g. `'read:document'` or `'tenant_a:write:doc\\:42'`.
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
      // Only the two escape sequences are recognised; anything else is
      // treated literally so an attacker-crafted `\x` doesn't silently
      // become `x`.
      if (next === ':' || next === '\\') {
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
