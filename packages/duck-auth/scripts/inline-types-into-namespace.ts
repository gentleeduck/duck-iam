#!/usr/bin/env bun
/**
 *
 * Inline flat exported types into their owning namespace, then rewrite
 * intra-file references + tests + downstream consumers to use the
 * namespaced form (`Namespace.IType`). Drops the now-redundant flat
 * export.
 *
 * Algorithm per source file:
 *   1. Parse the existing `export namespace X { type IFoo = Foo }`
 *      block. For each alias, capture (aliasName, fromName).
 *   2. Find the matching `export interface Foo {...}` or
 *      `export type Foo = ...` declaration in the same file.
 *   3. Move the body inside the namespace, renamed to the alias name,
 *      drop the alias line, drop the flat declaration.
 *   4. Replace every textual occurrence of the flat name in the owner
 *      file with `X.IFoo` (case-sensitive, word-boundaried),
 *      EXCLUDING JSDoc comments, namespace declaration headers, and
 *      import/export-from specifier lists.
 *   5. For every consumer file that imports the flat symbol FROM THE
 *      OWNER (same source path), rewrite the import to pull the
 *      namespace + qualify usages. Consumers that happen to share a
 *      name (e.g. a local declaration with the same identifier) are
 *      left alone.
 *
 * Run: `bun run scripts/inline-types-into-namespace.ts [--file path] [--check]`
 *
 * `--check` reports planned changes without writing. `--file` limits
 * processing to a single source (smoke-test new behaviour). Default:
 * walk every namespace owner.
 */

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve as pathResolve, relative } from 'node:path'

interface AliasPlan {
  /** Namespace owner name (e.g. `SamlProvider`). */
  owner: string
  /** Alias name inside the namespace (e.g. `IOptions`). */
  alias: string
  /** Flat source name (e.g. `SamlProviderOptions`). */
  flat: string
}

interface FilePlan {
  file: string
  owner: string
  aliases: AliasPlan[]
}

const CHECK = process.argv.includes('--check')
const fileArg = process.argv.find((a) => a.startsWith('--file='))?.slice('--file='.length)

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (e === 'node_modules' || e === 'dist' || e === '__tests__') continue
    const p = join(dir, e)
    const st = statSync(p)
    if (st.isDirectory()) walk(p, out)
    else if (e.endsWith('.ts') && !e.endsWith('.test.ts')) out.push(p)
  }
  return out
}

function walkAll(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (e === 'node_modules' || e === 'dist') continue
    const p = join(dir, e)
    const st = statSync(p)
    if (st.isDirectory()) walkAll(p, out)
    else if (e.endsWith('.ts')) out.push(p)
  }
  return out
}

/** Capture the first namespace block + its alias entries. */
function planForFile(file: string): FilePlan | null {
  const text = readFileSync(file, 'utf8')
  const nsMatch = text.match(/^export\s+namespace\s+(\w+)\s*\{([\s\S]*?)^\}/m)
  if (!nsMatch) return null
  const owner = nsMatch[1]!
  const body = nsMatch[2] ?? ''
  const aliases: AliasPlan[] = []
  // Doc'd aliases.
  for (const m of body.matchAll(
    /^\s*\/\*\*[\s\S]*?\*\/\s*\n\s*export\s+type\s+(\w+)(?:<[^>]*>)?\s*=\s*(\w+)(?:<[^>]*>)?\s*$/gm,
  )) {
    aliases.push({ owner, alias: m[1]!, flat: m[2]! })
  }
  // Un-doc'd aliases.
  for (const m of body.matchAll(/^\s*export\s+type\s+(\w+)(?:<[^>]*>)?\s*=\s*(\w+)(?:<[^>]*>)?\s*$/gm)) {
    if (!aliases.find((a) => a.alias === m[1])) {
      aliases.push({ owner, alias: m[1]!, flat: m[2]! })
    }
  }
  return aliases.length === 0 ? null : { file, owner, aliases }
}

/**
 * Resolve a relative import specifier from `fromFile` and check whether
 * it points at `targetFile`. Accepts the same shapes a bundler does:
 * raw path, `.ts` extension, or `/index.ts` directory shorthand.
 */
function importResolvesTo(specifier: string, fromFile: string, targetFile: string): boolean {
  if (!specifier.startsWith('.')) return false
  const base = pathResolve(dirname(fromFile), specifier)
  const target = pathResolve(targetFile)
  if (base === target) return true
  if (base + '.ts' === target) return true
  if (base + '.tsx' === target) return true
  if (join(base, 'index.ts') === target) return true
  if (join(base, 'index.tsx') === target) return true
  return false
}

/**
 * Rewrite `flat` -> `owner.alias` in `text`, but ONLY on lines that are
 * not JSDoc, not import/export-from specifier lists, and not the
 * `export namespace X` declaration header. This keeps the rewriter from
 * corrupting unrelated namespace declarations and from rewriting the
 * literal name inside doc comments.
 */
function rewriteFlatRefs(text: string, replacements: Array<{ flat: string; replacement: string }>): string {
  const lines = text.split('\n')
  const out: string[] = []
  let inJsdoc = false
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]!
    const trimmed = line.trimStart()

    // Track JSDoc state.
    if (!inJsdoc && trimmed.startsWith('/**')) {
      inJsdoc = !line.includes('*/') || line.indexOf('*/') < line.indexOf('/**')
    }
    if (inJsdoc) {
      out.push(line)
      if (line.includes('*/')) inJsdoc = false
      continue
    }

    // Skip single-line `// ...` comments entirely - leave the line alone.
    if (trimmed.startsWith('//')) {
      out.push(line)
      continue
    }

    // Skip namespace declaration headers (`export namespace X` or `namespace X`).
    if (/^\s*(?:export\s+)?namespace\s+\w+\s*\{/.test(line)) {
      out.push(line)
      continue
    }

    // Skip import/export-from specifier lines (handled separately by the
    // consumer-patch phase, which is aware of the source module).
    if (/^\s*(?:import|export)\b.*\bfrom\s+['"]/.test(line)) {
      out.push(line)
      continue
    }

    for (const r of replacements) {
      const re = new RegExp(`(?<![\\w.])${r.flat}(?![\\w])`, 'g')
      line = line.replace(re, r.replacement)
    }
    out.push(line)
  }
  return out.join('\n')
}

/**
 * Look backward from `headerStart` for a JSDoc block (`/**...*\/`)
 * positioned immediately above the declaration (no other non-comment
 * content between). Returns the index where the JSDoc starts, or
 * `headerStart` when no such block exists.
 */
function findPrecedingJsdoc(text: string, headerStart: number): number {
  const before = text.slice(0, headerStart)
  const lastJsdocEnd = before.lastIndexOf('*/')
  if (lastJsdocEnd === -1) return headerStart
  // Only whitespace may sit between the `*/` and the header.
  const tail = before.slice(lastJsdocEnd + 2)
  if (tail.trim() !== '') return headerStart
  const jsdocStartIdx = before.lastIndexOf('/**', lastJsdocEnd)
  if (jsdocStartIdx === -1) return headerStart
  // The doc block must not span past another declaration/import/etc.
  // i.e. the slice between `/**` and `*/` should look like a comment.
  // We've already required only whitespace after `*/`, so the only check
  // left is that nothing precedes `/**` on the same line beyond whitespace.
  const lineStart = before.lastIndexOf('\n', jsdocStartIdx - 1) + 1
  const linePrefix = before.slice(lineStart, jsdocStartIdx)
  if (linePrefix.trim() !== '') return headerStart
  return jsdocStartIdx
}

/** Pull a single `export interface Foo { ... }` block by name. */
function extractInterface(
  text: string,
  name: string,
): { match: string; body: string; generics: string; extendsClause: string } | null {
  const headerRe = new RegExp(`^export\\s+interface\\s+${name}(<[^>]+>)?(\\s+extends[^{]+?)?\\s*\\{`, 'm')
  const headerMatch = headerRe.exec(text)
  if (!headerMatch) return null
  const headerStart = headerMatch.index
  const bodyStart = headerStart + headerMatch[0].length
  // Walk forward with a brace counter to find the matching close.
  let depth = 1
  let i = bodyStart
  while (i < text.length && depth > 0) {
    const ch = text[i]
    if (ch === '{') depth++
    else if (ch === '}') depth--
    i++
  }
  if (depth !== 0) return null
  const closingBraceIdx = i - 1
  const body = text.slice(bodyStart, closingBraceIdx)
  const docStart = findPrecedingJsdoc(text, headerStart)
  const match = text.slice(docStart, closingBraceIdx + 1)
  const extendsClause = (headerMatch[2] ?? '').replace(/\s+$/, '')
  return { match, body, generics: headerMatch[1] ?? '', extendsClause }
}

/** Pull a single `export type Foo = ...` declaration by name (multi-line aware). */
function extractTypeAlias(text: string, name: string): { match: string; rhs: string; generics: string } | null {
  const headerRe = new RegExp(`^export\\s+type\\s+${name}(<[^>]+>)?\\s*=\\s*`, 'm')
  const headerMatch = headerRe.exec(text)
  if (!headerMatch) return null
  const headerStart = headerMatch.index
  const rhsStart = headerStart + headerMatch[0].length
  // Walk forward tracking bracket depth; terminate when we hit a newline
  // at depth 0 followed by another top-level declaration (export/{}, etc.)
  // or by a blank line.
  let depth = 0
  let endIdx = rhsStart
  for (let i = rhsStart; i < text.length; i++) {
    const ch = text[i]
    // Track only the brackets that can hold a `\n` without ending the RHS.
    // Angle brackets are skipped: `=>` and `Foo<Bar>` would otherwise
    // confuse a naive counter, and generics never carry standalone newlines
    // that would be misread as terminators.
    if (ch === '{' || ch === '(' || ch === '[') depth++
    else if (ch === '}' || ch === ')' || ch === ']') {
      if (depth === 0) {
        endIdx = i
        break
      }
      depth--
    } else if (ch === '\n' && depth === 0) {
      // Peek ahead: blank line, EOF, or next top-level export ends the RHS.
      let j = i + 1
      while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j++
      if (j >= text.length || text[j] === '\n') {
        endIdx = i
        break
      }
      const ahead = text.slice(j, j + 7)
      if (ahead.startsWith('export ') || ahead.startsWith('/**') || ahead.startsWith('}')) {
        endIdx = i
        break
      }
    }
    endIdx = i + 1
  }
  // Trim trailing whitespace.
  while (endIdx > rhsStart && /\s/.test(text.charAt(endIdx - 1))) endIdx--
  const rhs = text.slice(rhsStart, endIdx).trim()
  const docStart = findPrecedingJsdoc(text, headerStart)
  const match = text.slice(docStart, endIdx)
  return { match, rhs, generics: headerMatch[1] ?? '' }
}

/** Re-indent a captured interface body so its members sit 4 spaces deep
 * (inside `namespace { interface { ... } }`). The captured body keeps its
 * leading newline; we strip one leading level of common indentation if
 * present, then add a fixed 4-space indent. */
function reindentBody(body: string): string {
  const lines = body.split('\n')
  // Determine the minimum non-empty indentation among existing lines.
  let minIndent = Number.POSITIVE_INFINITY
  for (const l of lines) {
    if (!l.trim()) continue
    const m = l.match(/^( *)/)
    if (m && m[1].length < minIndent) minIndent = m[1].length
  }
  if (!Number.isFinite(minIndent)) minIndent = 0
  return lines
    .map((l) => {
      if (!l.trim()) return ''
      return '    ' + l.slice(minIndent)
    })
    .join('\n')
}

function transform(plan: FilePlan): string | null {
  const text = readFileSync(plan.file, 'utf8')
  let next = text

  // Collect the inline bodies we will insert into the namespace.
  const namespaceMembers: string[] = []
  for (const a of plan.aliases) {
    const iface = extractInterface(next, a.flat)
    if (iface) {
      // Pop the flat declaration.
      next = next.replace(iface.match, '')
      const body = reindentBody(iface.body)
      namespaceMembers.push(`  export interface ${a.alias}${iface.generics}${iface.extendsClause} {\n${body}\n  }`)
      continue
    }
    const ty = extractTypeAlias(next, a.flat)
    if (ty) {
      next = next.replace(ty.match, '')
      namespaceMembers.push(`  export type ${a.alias}${ty.generics} = ${ty.rhs}`)
      continue
    }
    // Could not locate the flat declaration - leave the file untouched
    // for this alias (it likely points at an imported type or a
    // generic from a sibling module).
    return null
  }

  // Rebuild the namespace block: drop the existing aliases, insert the
  // inlined member declarations. Match the existing block, then replace
  // its body content.
  const nsRe = new RegExp(`(export\\s+namespace\\s+${plan.owner}\\s*\\{)([\\s\\S]*?)(\\n\\})`)
  const nsMatch = next.match(nsRe)
  if (!nsMatch) return null
  const newBody = '\n' + namespaceMembers.join('\n\n') + '\n'
  next = next.replace(nsRe, `$1${newBody}$3`)

  // Replace remaining intra-file refs to the flat names with namespace
  // form, but skip JSDoc / namespace headers / import-from lines.
  const replacements = plan.aliases.map((a) => ({ flat: a.flat, replacement: `${plan.owner}.${a.alias}` }))
  next = rewriteFlatRefs(next, replacements)

  return next
}

/** Update consumer files to swap flat imports for namespace imports.
 * Owner files are also swept here, since an owner can consume ANOTHER
 * owner's flat types. The owner's own plan is filtered out per-file so
 * the script doesn't re-rewrite intra-file refs `transform()` already
 * handled. */
function patchConsumers(rootDir: string, plans: FilePlan[]): number {
  const allFiles = walkAll(rootDir)
  const planByFile = new Map(plans.map((p) => [p.file, p] as const))
  let touched = 0
  for (const file of allFiles) {
    const selfPlan = planByFile.get(file)
    // Plans relevant to this file = every plan except its own.
    const otherPlans = selfPlan ? plans.filter((p) => p !== selfPlan) : plans
    let text = readFileSync(file, 'utf8')
    const beforeAll = text

    // Pass 1: rewrite import/export-from specifier lists where the
    // source resolves to a known owner file (excluding the file's own).
    const fromRe = /(\b(?:import|export)\b\s*)(type\s+)?\{([^}]*)\}\s+from\s+(['"][^'"]+['"])/g
    type RewriteOp = { flat: string; owner: string; alias: string }
    const opsForThisFile: RewriteOp[] = []
    text = text.replace(
      fromRe,
      (full, prefix: string, typeKw: string | undefined, names: string, srcQuoted: string) => {
        const src = srcQuoted.slice(1, -1)
        const owningPlan = otherPlans.find((p) => importResolvesTo(src, file, p.file))
        if (!owningPlan) return full
        const importable = new Set(owningPlan.aliases.map((a) => a.flat))
        const tokens = names
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
        const surviving: string[] = []
        let added = false
        for (const tok of tokens) {
          const m = tok.match(/^(?:type\s+)?(\w+)$/)
          if (!m) {
            surviving.push(tok)
            continue
          }
          const name = m[1]!
          const alias = owningPlan.aliases.find((a) => a.flat === name)
          if (alias && importable.has(name)) {
            added = true
            opsForThisFile.push({ flat: name, owner: owningPlan.owner, alias: alias.alias })
            continue
          }
          surviving.push(tok)
        }
        if (added) {
          const ownerToken = `${typeKw ? '' : 'type '}${owningPlan.owner}`
          if (!surviving.some((t) => t === owningPlan.owner || t === `type ${owningPlan.owner}`)) {
            surviving.push(ownerToken)
          }
        }
        if (surviving.length === 0) return ''
        // Reassemble. Preserve `type` keyword stickiness on the whole list.
        return `${prefix}${typeKw ?? ''}{ ${surviving.join(', ')} } from ${srcQuoted}`
      },
    )

    // Pass 2: rewrite remaining usages for names we just removed from
    // import lists - but ONLY those names, and never inside JSDoc,
    // namespace headers, or import-from lines.
    if (opsForThisFile.length > 0) {
      text = rewriteFlatRefs(
        text,
        opsForThisFile.map((o) => ({ flat: o.flat, replacement: `${o.owner}.${o.alias}` })),
      )
    }

    if (text !== beforeAll) {
      if (!CHECK) writeFileSync(file, text)
      touched++
      console.log(`patched consumer ${relative(rootDir, file)}`)
    }
  }
  return touched
}

const rootSrc = 'src'
const ownerFiles = fileArg ? [fileArg] : walk(rootSrc)
const plans: FilePlan[] = []
for (const f of ownerFiles) {
  const plan = planForFile(f)
  if (plan) plans.push(plan)
}

console.log(`planning refactor for ${plans.length} namespace owners`)

let ownersTouched = 0
for (const plan of plans) {
  const out = transform(plan)
  if (!out) {
    console.log(`SKIP ${relative('.', plan.file)} - extraction failed for one or more aliases`)
    continue
  }
  if (!CHECK) writeFileSync(plan.file, out)
  ownersTouched++
}
console.log(`refactored ${ownersTouched} owner files`)

const consumersTouched = patchConsumers(rootSrc, plans)
console.log(`patched ${consumersTouched} consumer files`)

if (CHECK) console.log('\n(check mode; no files were written)')
