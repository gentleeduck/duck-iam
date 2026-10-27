/**
 * Show which files landed in which cluster, so a count can be checked instead
 * of trusted. A cluster whose membership you have not read is a number you
 * cannot defend.
 *
 *   bun benchmark/scripts/audit.ts <harvest.json> [cluster-key]
 */

import { readFileSync } from 'node:fs'
import type { Harvest } from './harvest'

const [path, only] = process.argv.slice(2)
if (!path) {
  console.error('usage: bun audit.ts <harvest.json> [cluster-key]')
  process.exit(2)
}

const h: Harvest = JSON.parse(readFileSync(path, 'utf8'))
const byCluster = new Map<string, typeof h.files>()
for (const f of h.files) {
  if (!byCluster.has(f.cluster)) byCluster.set(f.cluster, [])
  byCluster.get(f.cluster)!.push(f)
}

const keys = [...byCluster.keys()].sort(
  (a, b) => byCluster.get(b)!.reduce((n, f) => n + f.tests, 0) - byCluster.get(a)!.reduce((n, f) => n + f.tests, 0),
)

for (const key of keys) {
  if (only && key !== only) continue
  const files = byCluster.get(key)!
  const tests = files.reduce((n, f) => n + f.tests, 0)
  console.log(`\n=== ${key}  (${files.length} files, ${tests} tests)`)
  for (const f of files.sort((a, b) => b.tests - a.tests)) {
    console.log(`  ${String(f.tests).padStart(4)}  ${f.path}`)
  }
}
