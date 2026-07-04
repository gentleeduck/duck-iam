#!/usr/bin/env bun
/**
 *
 * Audit + auto-fix pass that walks every `src/**\/*.ts` file (excluding
 * `__tests__`), enumerates flat-exported interfaces / types / classes /
 * functions, and ensures that every PUBLIC type has a namespace alias of
 * the form `Owner.IX = X`. The owner namespace name is inferred from the
 * primary class / function in the file when present; otherwise from the
 * basename.
 *
 * Run: `bun run scripts/audit-namespaces.ts` (also runs by default at
 * pre-release; CI can run it with `--check` to fail on missing aliases
 * instead of writing them).
 */

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

interface Decl {
  kind: 'interface' | 'type' | 'class' | 'function' | 'const'
  name: string
}

interface AuditResult {
  file: string
  ownerName: string
  flat: Decl[]
  namespaceAliases: Set<string> // names of types aliased
  hasNamespaceBlock: boolean
  missing: FlatDecl[] // flat interface/type without a namespace alias
}

const CHECK_ONLY = process.argv.includes('--check')

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === '__tests__' || entry === 'node_modules' || entry === 'dist') continue
    const p = join(dir, entry)
    const st = statSync(p)
    if (st.isDirectory()) walk(p, out)
    else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) out.push(p)
  }
  return out
}

/** Per-file overrides for the inferred owner symbol. */
const OWNER_OVERRIDES: Record<string, string> = {
  'src/providers/passkey/types.ts': 'PasskeyTypes',
  'src/providers/oauth/github/index.ts': 'Githuboauth',
  'src/providers/oauth/google/index.ts': 'Googleoauth',
  'src/providers/oauth/core/refresh.ts': 'oauthRefresh',
  'src/providers/oauth/core/state.ts': 'oauthState',
  'src/providers/oauth/core/provider.ts': 'oauthProvider',
  'src/providers/oauth/core/client.ts': 'oauthClient',
  'src/core/types/context.ts': 'TenantContext',
}

function inferOwner(file: string, decls: Decl[]): string {
  if (OWNER_OVERRIDES[file]) return OWNER_OVERRIDES[file]!
  // Prefer first exported class, then first exported function (PascalCased).
  const cls = decls.find((d) => d.kind === 'class')
  if (cls) return cls.name
  const fn = decls.find((d) => d.kind === 'function' && /^[a-z]/.test(d.name[0] ?? ''))
  if (fn) return fn.name[0]!.toUpperCase() + fn.name.slice(1)
  // Fallback: basename PascalCased.
  const base = file
    .replace(/.*\//, '')
    .replace(/\.ts$/, '')
    .replace(/(^|-)(\w)/g, (_, _d, c) => c.toUpperCase())
  return base
}

interface FlatDecl extends Decl {
  /** Generic parameters string captured as written (`<Profile = unknown>` etc), or null when none. */
  generics: string | null
}

function audit(file: string): AuditResult {
  const text = readFileSync(file, 'utf8')
  const flat: FlatDecl[] = []
  for (const m of text.matchAll(/^export\s+interface\s+(\w+)(<[^>]+>)?/gm))
    flat.push({ kind: 'interface', name: m[1]!, generics: m[2] ?? null })
  for (const m of text.matchAll(/^export\s+type\s+(\w+)(<[^>]+>)?\s*=/gm))
    flat.push({ kind: 'type', name: m[1]!, generics: m[2] ?? null })
  for (const m of text.matchAll(/^export\s+class\s+(\w+)/gm)) flat.push({ kind: 'class', name: m[1]!, generics: null })
  for (const m of text.matchAll(/^export\s+(?:async\s+)?function\s+(\w+)/gm))
    flat.push({ kind: 'function', name: m[1]!, generics: null })
  for (const m of text.matchAll(/^export\s+const\s+([A-Z]\w*)/gm))
    flat.push({ kind: 'const', name: m[1]!, generics: null })

  const namespaceAliases = new Set<string>()
  // Names already taken on the LHS of an alias inside a namespace; needed
  // so we don't emit `export type IConfig = ...` when an IConfig already
  // exists with different generics.
  const existingAliasNames = new Set<string>()
  let hasNamespaceBlock = false
  let existingNamespaceName: string | null = null
  const nsBlockRe = /^export\s+namespace\s+(\w+)\s*\{([\s\S]*?)^\}/gm
  for (const nsMatch of text.matchAll(nsBlockRe)) {
    hasNamespaceBlock = true
    existingNamespaceName ??= nsMatch[1]!
    const body = nsMatch[2] ?? ''
    for (const aliasMatch of body.matchAll(/export\s+type\s+(\w+)(?:<[^>]+>)?\s*=\s*(\w+)/g)) {
      existingAliasNames.add(aliasMatch[1]!)
      namespaceAliases.add(aliasMatch[2]!)
    }
  }

  // Prefer the existing namespace name over the inferred one - the file
  // owner has already chosen the canonical symbol.
  const ownerName = existingNamespaceName ?? inferOwner(file, flat)
  const missing: FlatDecl[] = flat.filter((d) => {
    if (d.kind !== 'interface' && d.kind !== 'type') return false
    if (d.name === ownerName) return false
    if (namespaceAliases.has(d.name)) return false
    // Also skip when the would-be alias name is already taken inside the
    // namespace under different generics - that would create a duplicate
    // identifier error.
    const proposed = generateAlias(d.name, ownerName)
    if (existingAliasNames.has(proposed)) return false
    return true
  })

  return { file, ownerName, flat, namespaceAliases, hasNamespaceBlock, missing }
}

function aliasName(typeName: string): string {
  // Strip the owner's prefix when the type starts with it.
  return `I${typeName.replace(/^[A-Z][a-z]+(?=[A-Z])/, '')}`
}

function generateAlias(typeName: string, owner: string): string {
  // Common patterns: FooConfig -> IConfig, FooOptions -> IOptions, FooBeginInput -> IBeginInput
  const stripped = typeName.startsWith(owner) ? typeName.slice(owner.length) : typeName
  if (!stripped) return 'I'
  return `I${stripped}`
}

function appendAliases(file: string, owner: string, missing: FlatDecl[]): void {
  const lines: string[] = ['']
  lines.push('/**')
  lines.push(` * Namespace merge for \`${owner}\`. Co-locates the flat type exports`)
  lines.push(' * alongside the primary symbol via TS class+namespace merging.')
  lines.push(' *')
  lines.push(' */')
  lines.push(`export namespace ${owner} {`)
  for (const d of missing) {
    const alias = generateAlias(d.name, owner)
    lines.push(`  /** Alias for the flat \`${d.name}\` type. */`)
    lines.push(`  export type ${alias} = ${d.name}`)
  }
  lines.push('}')
  lines.push('')
  const text = readFileSync(file, 'utf8')
  // If a namespace block already exists for owner, append inside; else append at EOF.
  const blockRe = new RegExp(`(export\\s+namespace\\s+${owner}\\s*\\{)([\\s\\S]*?)(\\n\\})`, 'm')
  const match = text.match(blockRe)
  if (match) {
    const additions = missing
      .map((d) => {
        const alias = generateAlias(d.name, owner)
        // Preserve generics when present so the alias keeps the same arity.
        const lhs = d.generics ? `${alias}${d.generics}` : alias
        const rhs = d.generics
          ? `${d.name}<${d.generics
              .slice(1, -1)
              .split(',')
              .map((seg) =>
                seg
                  .trim()
                  .split(/\s*=\s*/)[0]!
                  .replace(/\s+extends\s+.*$/, ''),
              )
              .join(', ')}>`
          : d.name
        return `  /** Alias for the flat \`${d.name}\` type. */\n  export type ${lhs} = ${rhs}`
      })
      .join('\n')
    const updated = text.replace(blockRe, `$1$2\n${additions}$3`)
    writeFileSync(file, updated)
  } else {
    writeFileSync(file, text + lines.join('\n'))
  }
}

const root = 'src'
const files = walk(root)
const results = files.map(audit)
const withMissing = results.filter((r) => r.missing.length > 0)

if (withMissing.length === 0) {
  console.log('namespace audit OK; every flat type has a namespace alias.')
  process.exit(0)
}

for (const r of withMissing) {
  console.log(`${r.file} (owner ${r.ownerName}) missing aliases for:`)
  for (const m of r.missing)
    console.log(`  - ${m.kind} ${m.name} -> ${r.ownerName}.${generateAlias(m.name, r.ownerName)}`)
}

if (CHECK_ONLY) {
  console.log(`\n${withMissing.length} files have missing aliases. Run without --check to write.`)
  process.exit(1)
}

for (const r of withMissing) appendAliases(r.file, r.ownerName, r.missing)
console.log(`\nWrote aliases for ${withMissing.length} files.`)
