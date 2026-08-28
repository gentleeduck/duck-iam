import { scopeAncestors } from '../engine.libs'

export interface ScopeMask {
  readonly allow: number
  readonly deny: number
}

export function buildScopeTrie(
  grants: readonly { scope: string; allow: number; deny: number }[],
): Map<string, ScopeMask> {
  const trie = new Map<string, { allow: number; deny: number }>()
  for (const g of grants) {
    const existing = trie.get(g.scope)
    if (existing) {
      trie.set(g.scope, { allow: existing.allow | g.allow, deny: existing.deny | g.deny })
    } else {
      trie.set(g.scope, { allow: g.allow, deny: g.deny })
    }
  }
  return trie
}

/**
 * `'union'`: OR every matching ancestor level's mask in (org + team grants both apply).
 * `'override'`: stop at the first (most specific) matching level.
 * Mirrors `enrichSubjectWithScopedRoles`'s `scopeCombine` (engine.libs.ts) at the mask level.
 */
export function resolveScopeMask(
  trie: ReadonlyMap<string, ScopeMask>,
  scope: string,
  combine: 'union' | 'override',
): ScopeMask {
  let allow = 0
  let deny = 0
  for (const level of scopeAncestors(scope)) {
    const hit = trie.get(level)
    if (!hit) continue
    allow |= hit.allow
    deny |= hit.deny
    if (combine === 'override') break
  }
  return { allow, deny }
}
