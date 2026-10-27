/**
 * Diff two harvests by feature cluster and write the gap report.
 *
 *   bun benchmark/scripts/compare.ts benchmark/out/duck-auth.json benchmark/out/better-auth.json
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { CLUSTERS, type Scope } from './clusters'
import type { Harvest } from './harvest'

interface Row {
  key: string
  label: string
  scope: Scope | 'unknown'
  duck: number
  duckFiles: number
  ba: number
  baFiles: number
  note?: string
}

const SCOPE_ORDER: Record<string, number> = {
  shared: 0,
  'ba-only-gap': 1,
  'ba-only-by-design': 2,
  'duck-only': 3,
  unknown: 4,
}

/** An unrecognised scope sorts last rather than throwing the comparator off. */
function scopeRank(scope: string): number {
  return SCOPE_ORDER[scope] ?? Number.MAX_SAFE_INTEGER
}

function tally(h: Harvest, key: string) {
  const files = h.files.filter((f) => f.cluster === key)
  return { files: files.length, tests: files.reduce((n, f) => n + f.tests, 0) }
}

/** `+n%` means duck-auth has more. Infinity when better-auth has none. */
function ratio(duck: number, ba: number): string {
  if (ba === 0 && duck === 0) return '—'
  if (ba === 0) return 'duck only'
  if (duck === 0) return 'BA only'
  const r = duck / ba
  return r >= 1 ? `duck ${r.toFixed(1)}x` : `BA ${(1 / r).toFixed(1)}x`
}

function main() {
  const [duckPath, baPath] = process.argv.slice(2)
  if (!duckPath || !baPath) {
    console.error('usage: bun compare.ts <duck.json> <better-auth.json>')
    process.exit(2)
  }
  const duck: Harvest = JSON.parse(readFileSync(duckPath, 'utf8'))
  const ba: Harvest = JSON.parse(readFileSync(baPath, 'utf8'))

  // A `ba-only-*` cluster holding a duck-auth file, or a `duck-only` cluster
  // holding a better-auth one, means a pattern is catching the wrong repo and
  // every number below it is wrong. Fail here rather than publish the table.
  const scopeOf = new Map(CLUSTERS.map((c) => [c.key, c.scope]))
  const violations: string[] = []
  for (const f of duck.files) {
    const s = scopeOf.get(f.cluster)
    if (s === 'ba-only-gap' || s === 'ba-only-by-design') violations.push(`duck-auth file in ${f.cluster} (${s}): ${f.path}`)
  }
  for (const f of ba.files) {
    if (scopeOf.get(f.cluster) === 'duck-only') violations.push(`better-auth file in ${f.cluster} (duck-only): ${f.path}`)
  }
  if (violations.length > 0) {
    console.error(`cross-scope misfiling — fix clusters.ts before trusting any count:\n  ${violations.join('\n  ')}`)
    process.exit(1)
  }

  const rows: Row[] = CLUSTERS.map((c) => {
    const d = tally(duck, c.key)
    const b = tally(ba, c.key)
    return { key: c.key, label: c.label, scope: c.scope, duck: d.tests, duckFiles: d.files, ba: b.tests, baFiles: b.files, note: c.note }
  })

  const unclassifiedDuck = tally(duck, 'unclassified')
  const unclassifiedBa = tally(ba, 'unclassified')
  if (unclassifiedDuck.tests + unclassifiedBa.tests > 0) {
    rows.push({
      key: 'unclassified',
      label: 'UNCLASSIFIED (tighten clusters.ts)',
      scope: 'unknown',
      duck: unclassifiedDuck.tests,
      duckFiles: unclassifiedDuck.files,
      ba: unclassifiedBa.tests,
      baFiles: unclassifiedBa.files,
    })
  }

  rows.sort((a, b) => scopeRank(a.scope) - scopeRank(b.scope) || b.ba - a.ba || b.duck - a.duck)

  const out: string[] = []
  out.push('# Coverage gap: duck-auth vs better-auth')
  out.push('')
  out.push(`Generated ${new Date().toISOString().slice(0, 10)} by \`benchmark/scripts/compare.ts\`. Do not hand-edit.`)
  out.push('')
  out.push(`- **duck-auth**: ${duck.totals.files} files, ${duck.totals.tests} tests`)
  out.push(`- **better-auth**: ${ba.totals.files} files, ${ba.totals.tests} tests`)
  out.push('')
  out.push('`scope` is the honest part of this table. A zero under a `by-design` row is a boundary, not a hole.')
  out.push('')

  const sections: [Scope | 'unknown', string, string][] = [
    ['shared', 'Both implement it — a difference here is a real coverage difference', ''],
    ['ba-only-gap', 'better-auth has it, duck-auth does not — candidate gaps', ''],
    ['ba-only-by-design', 'better-auth has it, duck-auth deliberately does not', ''],
    ['duck-only', 'duck-auth has it, better-auth has no counterpart', ''],
    ['unknown', 'Unclassified', ''],
  ]

  for (const [scope, heading] of sections) {
    const group = rows.filter((r) => r.scope === scope)
    if (group.length === 0) continue
    out.push(`## ${heading}`)
    out.push('')
    out.push('| Cluster | duck-auth | better-auth | Lead |')
    out.push('| --- | --- | --- | --- |')
    for (const r of group) {
      out.push(`| ${r.label} | ${r.duck} (${r.duckFiles}f) | ${r.ba} (${r.baFiles}f) | ${ratio(r.duck, r.ba)} |`)
    }
    const dt = group.reduce((n, r) => n + r.duck, 0)
    const bt = group.reduce((n, r) => n + r.ba, 0)
    out.push(`| **subtotal** | **${dt}** | **${bt}** | ${ratio(dt, bt)} |`)
    out.push('')
    for (const r of group.filter((x) => x.note)) out.push(`- *${r.label}*: ${r.note}`)
    if (group.some((x) => x.note)) out.push('')
  }

  writeFileSync('benchmark/out/GAP-TABLE.md', out.join('\n'))
  console.log(out.join('\n'))
}

main()
