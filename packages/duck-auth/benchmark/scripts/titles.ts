/**
 * Dump every test title from the files matching a path pattern, with its
 * enclosing describe. This is the input to porting a scenario: a count tells you
 * a gap exists, a title tells you what to write.
 *
 *   bun benchmark/scripts/titles.ts <repo-root> <path-substring-or-regex>
 *
 * Reads only. Nothing from the target repo is imported or executed.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const TEST_FILE = /\.(test|spec)\.(ts|tsx|mts|cts)$/
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.turbo', 'coverage', '.next', 'build'])

/**
 * A test or suite opener and its title.
 *
 * NOTE: POSIX classes, not `\s`. BSD grep has no `\s`, and matching this with a
 * shell grep instead of here is how an extraction sweep silently returns nothing.
 */
const OPENER = /^[ \t]*(describe|it|test)((?:\.[a-zA-Z]+)*)[ \t]*\([ \t]*(['"`])([\s\S]*?)\3/

function walk(dir: string, acc: string[] = []): string[] {
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return acc
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue
    const full = join(dir, entry)
    let st: ReturnType<typeof statSync>
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) walk(full, acc)
    else if (TEST_FILE.test(entry)) acc.push(full)
  }
  return acc
}

const [root, pattern] = process.argv.slice(2)
if (!root || !pattern) {
  console.error('usage: bun titles.ts <repo-root> <path-substring-or-regex>')
  process.exit(2)
}

const re = new RegExp(pattern)
let files = 0
let titles = 0

for (const abs of walk(root).sort()) {
  const rel = relative(root, abs).split(sep).join('/')
  if (!re.test(rel)) continue

  const lines = readFileSync(abs, 'utf8').split('\n')
  const found: string[] = []
  // Indentation is the only cheap signal for nesting depth; it is good enough to
  // show which describe a case sits under.
  for (const line of lines) {
    const m = OPENER.exec(line)
    if (!m) continue
    const kind = m[1]
    const mods = m[2] ?? ''
    const title = (m[4] ?? '').replace(/\s+/g, ' ').trim()
    if (!title) continue
    const indent = ' '.repeat(Math.max(0, (line.match(/^[ \t]*/)?.[0].length ?? 0)))
    found.push(`${indent}${kind}${mods}: ${title}`)
    if (kind !== 'describe') titles++
  }
  if (found.length === 0) continue
  files++
  console.log(`\n### ${rel}`)
  for (const f of found) console.log(f)
}

console.error(`\n(${files} files, ${titles} test titles)`)
