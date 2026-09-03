/**
 * Regenerates `docs/TEST-INVENTORY.md` from the tests themselves.
 *
 * The file used to say "This is a snapshot, not generated - update it by hand".
 * It drifted from 93 files to 189 without anyone noticing, and the 96 missing
 * entries were the round-1 security-fix tests: the inventory was at its least
 * accurate about exactly the tests that mattered most. Hand maintenance was the
 * defect, not the symptom.
 *
 *   bun run gen:test-inventory          # rewrite the file
 *   bun run gen:test-inventory --check  # exit 1 if it is stale (CI / the suite)
 *
 * Counts come from vitest's JSON reporter, so `it.each` rows count individually,
 * matching what the old hand-captured numbers meant.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'

const PKG = join(import.meta.dirname, '..')
const OUT = join(PKG, 'docs/TEST-INVENTORY.md')

/** Area buckets, first match wins - order matters. */
const AREAS: readonly (readonly [string, RegExp])[] = [
  ['Core / compiled engine', /^core\/engine\/compiled\//],
  ['Adapters', /^adapters\//],
  ['Clients', /^client\//],
  ['Core', /^core\//],
  ['Devtools', /^dt\//],
  ['Invalidators', /^invalidators\//],
  ['Observability', /^observability\//],
  ['Server', /^server\//],
  ['Shared', /^shared\//],
  ['Package surface', /^__tests__\//],
]

function areaOf(file: string): string {
  for (const [name, re] of AREAS) if (re.test(file)) return name
  return 'Other'
}

interface IFile {
  readonly file: string
  readonly tests: number
  readonly covers: string
}

/** The file's first top-level `describe(...)` string - what it says it tests. */
function coversOf(absolute: string): string {
  let src: string
  try {
    src = readFileSync(absolute, 'utf8')
  } catch {
    return ''
  }
  const m = /^describe(?:\.\w+)?\(\s*(['"`])([\s\S]*?)\1/m.exec(src)
  return (m?.[2] ?? '').replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim()
}

function collect(): IFile[] {
  // A red suite still has to produce an inventory: the freshness test in
  // `src/__tests__` fails whenever a *new* test file is not yet listed, which
  // is precisely the moment you run this. Letting vitest's non-zero exit abort
  // generation would make the two deadlock. Failures are reported below.
  let raw: string
  try {
    raw = execFileSync('bunx', ['vitest', 'run', '--reporter=json'], {
      cwd: PKG,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
  } catch (err: unknown) {
    if (typeof err !== 'object' || err === null || !('stdout' in err) || typeof err.stdout !== 'string') throw err
    raw = err.stdout
  }
  // The reporter prints diagnostics before the JSON document; take from the
  // first `{` so a stray banner line does not break parsing.
  const start = raw.indexOf('{')
  if (start === -1) throw new Error('vitest produced no JSON')
  const parsed: unknown = JSON.parse(raw.slice(start))
  if (typeof parsed !== 'object' || parsed === null || !('testResults' in parsed)) {
    throw new Error('vitest JSON has no testResults')
  }
  const results: unknown = parsed.testResults
  if (!Array.isArray(results)) throw new Error('testResults is not an array')

  let failed = 0
  const out: IFile[] = []
  for (const entry of results) {
    if (typeof entry !== 'object' || entry === null) continue
    if (!('name' in entry) || typeof entry.name !== 'string') continue
    const assertions = 'assertionResults' in entry && Array.isArray(entry.assertionResults) ? entry.assertionResults : []
    const rel = relative(join(PKG, 'src'), entry.name)
    for (const a of assertions) {
      if (typeof a === 'object' && a !== null && 'status' in a && a.status === 'failed') failed++
    }
    out.push({ covers: coversOf(entry.name), file: rel, tests: assertions.length })
  }
  if (failed > 0) {
    console.warn(`warning: ${failed} test(s) failed - counts below reflect the run as it happened`)
  }
  return out.sort((a, b) => a.file.localeCompare(b.file))
}

function render(files: readonly IFile[]): string {
  const byArea = new Map<string, IFile[]>()
  for (const f of files) {
    const area = areaOf(f.file)
    const bucket = byArea.get(area)
    if (bucket === undefined) byArea.set(area, [f])
    else bucket.push(f)
  }

  const lines: string[] = [
    '# duck-iam — Test Inventory',
    '',
    'Every test file in `packages/duck-iam/src`, grouped by area, with what each',
    'one pins down.',
    '',
    '**This file is generated.** Do not edit it by hand - run',
    '`bun run gen:test-inventory` from `packages/duck-iam/`. The suite fails if it',
    'is stale (`src/__tests__/test-inventory-freshness.test.ts`), so it cannot',
    'drift the way the hand-maintained version did.',
    '',
    '| Column | Meaning |',
    '|---|---|',
    '| File | Path under `src/`, relative |',
    '| Tests | Assertion count from the vitest JSON reporter (`it.each` rows count individually) |',
    '| Covers | The file\'s first top-level `describe(...)` string |',
    '',
    '---',
    '',
  ]

  let totalFiles = 0
  let totalTests = 0
  const areaTotals: [string, number, number][] = []

  for (const [area] of [...AREAS, ['Other', /^/] as const]) {
    const bucket = byArea.get(area)
    if (bucket === undefined || bucket.length === 0) continue
    const subtotal = bucket.reduce((n, f) => n + f.tests, 0)
    areaTotals.push([area, bucket.length, subtotal])
    totalFiles += bucket.length
    totalTests += subtotal

    lines.push(`## ${area}`, '', '| File | Tests | Covers |', '|---|---|---|')
    for (const f of bucket) lines.push(`| \`${f.file}\` | ${f.tests} | ${f.covers} |`)
    lines.push(`| **Subtotal** | **${subtotal}** | |`, '', '---', '')
  }

  lines.push('## Totals by area', '', '| Area | Files | Tests |', '|---|---|---|')
  for (const [area, n, t] of areaTotals) lines.push(`| ${area} | ${n} | ${t} |`)
  lines.push(`| **Total** | **${totalFiles}** | **${totalTests}** |`, '')

  return lines.join('\n')
}

const rendered = render(collect())

if (process.argv.includes('--check')) {
  const current = readFileSync(OUT, 'utf8')
  if (current !== rendered) {
    console.error('docs/TEST-INVENTORY.md is stale - run `bun run gen:test-inventory`')
    process.exit(1)
  }
  console.log('docs/TEST-INVENTORY.md is up to date')
} else {
  writeFileSync(OUT, rendered)
  console.log(`wrote ${OUT}`)
}
