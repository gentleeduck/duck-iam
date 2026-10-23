/**
 * Emit a readable per-file test map from a harvest, grouped by cluster.
 *
 *   bun benchmark/scripts/map.ts benchmark/out/better-auth.json "better-auth v1.7.2" > benchmark/MAP-better-auth.md
 */

import { readFileSync } from 'node:fs'
import { CLUSTERS } from './clusters'
import type { Harvest } from './harvest'

const [path, title] = process.argv.slice(2)
if (!path) {
  console.error('usage: bun map.ts <harvest.json> [title]')
  process.exit(2)
}

const h: Harvest = JSON.parse(readFileSync(path, 'utf8'))
const order = [...CLUSTERS.map((c) => c.key), 'unclassified']

const out: string[] = []
out.push(`# Test map: ${title ?? h.label}`)
out.push('')
out.push(`Generated ${h.generatedAt} by \`benchmark/scripts/map.ts\`. Do not hand-edit.`)
out.push('')
out.push(
  `**${h.totals.files} test files, ${h.totals.tests} statically counted cases.** Static counting is a lower bound — see \`benchmark/README.md\`.`,
)
out.push('')

// A table of contents, so a 380-file map is navigable.
out.push('| Cluster | Files | Tests |')
out.push('| --- | --- | --- |')
for (const key of order) {
  const files = h.files.filter((f) => f.cluster === key)
  if (files.length === 0) continue
  const label = CLUSTERS.find((c) => c.key === key)?.label ?? 'UNCLASSIFIED'
  const tests = files.reduce((n, f) => n + f.tests, 0)
  out.push(`| [${label}](#${key}) | ${files.length} | ${tests} |`)
}
out.push('')

for (const key of order) {
  const files = h.files.filter((f) => f.cluster === key)
  if (files.length === 0) continue
  const cluster = CLUSTERS.find((c) => c.key === key)
  const tests = files.reduce((n, f) => n + f.tests, 0)

  out.push(`## ${key}`)
  out.push('')
  out.push(`${cluster?.label ?? 'UNCLASSIFIED'} — ${files.length} files, ${tests} tests, scope \`${cluster?.scope ?? 'unknown'}\`.`)
  if (cluster?.note) out.push(`\n> ${cluster.note}`)
  out.push('')
  out.push('| Tests | File | Suites |')
  out.push('| --- | --- | --- |')
  for (const f of [...files].sort((a, b) => b.tests - a.tests || a.path.localeCompare(b.path))) {
    // Suite titles carry the real subject matter; a handful is enough to place the file.
    const suites = f.suites
      .slice(0, 3)
      .map((s) => s.replace(/\|/g, '\\|'))
      .join('; ')
    const more = f.suites.length > 3 ? ` (+${f.suites.length - 3})` : ''
    const gated = f.runtimeSkips > 0 ? ' **[env-gated]**' : ''
    out.push(`| ${f.tests} | \`${f.path}\`${gated} | ${suites}${more} |`)
  }
  out.push('')
}

console.log(out.join('\n'))
