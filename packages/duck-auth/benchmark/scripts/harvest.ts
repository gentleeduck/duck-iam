/**
 * Harvest a test map from a repo: every test file, its test count, and the
 * feature cluster it belongs to.
 *
 * Reads only. Nothing from the target repo is imported, required or executed,
 * because one of the two targets is a third-party checkout.
 *
 *   bun benchmark/scripts/harvest.ts <repo-root> <label> [--out <file.json>] [--exclude docs,demo]
 */

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { classify } from './clusters'

const TEST_FILE = /\.(test|spec)\.(ts|tsx|mts|cts)$/
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.turbo', 'coverage', '.next', 'build'])

/** A line that opens a test case. Counts `it`, `test` and their modifiers. */
const TEST_OPEN = /^[ \t]*(it|test)(\.(each|skip|only|todo|fails|concurrent|sequential|runIf|skipIf|for))*[ \t]*[(`]/

/** A line that opens a suite, with its title when the title is a plain literal. */
const DESCRIBE_OPEN = /^[ \t]*describe(\.(each|skip|only|todo|concurrent|sequential|runIf|skipIf))*[ \t]*\(\s*(['"`])(.*?)\3/

/** `it.skip` / `test.todo` and friends: a declared test that never runs. */
const TEST_SKIPPED = /^[ \t]*(it|test)\.(skip|todo)\b/

/**
 * A bail-out that a count of `it(` cannot see, so a file can report tests it
 * never runs.
 *
 * WARN: the last alternative is the one that matters. `const suite = URL ? describe : describe.skip`
 * hides a whole file behind an env var and matches no `skipIf` grep, which is how
 * duck-auth's database tiers can vanish without a single failing line.
 */
const RUNTIME_SKIP =
  /\b(ctx|t|test|this)\s*\.\s*skip\s*\(|\b(describe|it|test)\.skipIf\b|\?\s*describe\s*:\s*describe\.skip|\bdescribe\.skip\b/

export interface FileRecord {
  path: string
  tests: number
  skipped: number
  runtimeSkips: number
  suites: string[]
  cluster: string
  clusterLabel: string
  scope: string
}

export interface Harvest {
  label: string
  root: string
  generatedAt: string
  files: FileRecord[]
  totals: { files: number; tests: number; skipped: number; runtimeSkips: number }
}

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

export function harvest(root: string, label: string, exclude: string[] = []): Harvest {
  const files: FileRecord[] = []

  for (const abs of walk(root).sort()) {
    const rel = relative(root, abs).split(sep).join('/')
    // The docs site and the demo app are not the library under comparison.
    if (exclude.some((p) => rel === p || rel.startsWith(`${p}/`))) continue
    const lines = readFileSync(abs, 'utf8').split('\n')

    let tests = 0
    let skipped = 0
    let runtimeSkips = 0
    const suites: string[] = []

    for (const line of lines) {
      if (TEST_OPEN.test(line)) {
        tests++
        if (TEST_SKIPPED.test(line)) skipped++
      }
      if (RUNTIME_SKIP.test(line)) runtimeSkips++
      const d = DESCRIBE_OPEN.exec(line)
      if (d?.[4]) suites.push(d[4])
    }

    const cluster = classify(rel)
    files.push({
      path: rel,
      tests,
      skipped,
      runtimeSkips,
      suites,
      cluster: cluster?.key ?? 'unclassified',
      clusterLabel: cluster?.label ?? 'UNCLASSIFIED',
      scope: cluster?.scope ?? 'unknown',
    })
  }

  return {
    label,
    root,
    generatedAt: new Date().toISOString().slice(0, 10),
    files,
    totals: {
      files: files.length,
      tests: files.reduce((n, f) => n + f.tests, 0),
      skipped: files.reduce((n, f) => n + f.skipped, 0),
      runtimeSkips: files.reduce((n, f) => n + f.runtimeSkips, 0),
    },
  }
}

if (import.meta.main) {
  const [root, label, ...rest] = process.argv.slice(2)
  if (!root || !label) {
    console.error('usage: bun harvest.ts <repo-root> <label> [--out <file.json>]')
    process.exit(2)
  }
  const outFlag = rest.indexOf('--out')
  const exFlag = rest.indexOf('--exclude')
  const excludeArg = exFlag === -1 ? undefined : rest[exFlag + 1]
  const outPath = outFlag === -1 ? undefined : rest[outFlag + 1]
  const exclude = excludeArg ? excludeArg.split(',').filter(Boolean) : []
  const result = harvest(root, label, exclude)
  const json = JSON.stringify(result, null, 2)
  if (outPath) {
    writeFileSync(outPath, json)
    const { files, tests, skipped, runtimeSkips } = result.totals
    console.log(
      `${label}: ${files} files, ${tests} tests (${skipped} statically skipped, ${runtimeSkips} runtime-skip sites) -> ${outPath}`,
    )
  } else {
    console.log(json)
  }
}
