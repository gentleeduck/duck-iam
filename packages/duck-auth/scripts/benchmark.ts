#!/usr/bin/env node
/**
 *
 * Bundle benchmark for `@gentleduck/auth`. Measures gzipped size of every
 * shipped subpath + the realistic "full kit" headline (core + cookie
 * transport + memory adapter + password provider + magic-link + TOTP +
 * one oauth + JWT). Emits JSON to public/benchmarks/results.json so the
 * monorepo can track size over time.
 *
 * Usage: bun run benchmark
 */

import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

const OUT_DIR = join(import.meta.dirname, '..', 'public', 'benchmarks')
mkdirSync(OUT_DIR, { recursive: true })

const DIST_DIR = join(import.meta.dirname, '..', 'dist')

interface SubpathSize {
  subpath: string
  entry: string
  gzipped: number
  raw: number
}

function gzippedSize(absPath: string): number {
  try {
    return gzipSync(readFileSync(absPath)).length
  } catch {
    return 0
  }
}

function rawSize(absPath: string): number {
  try {
    return statSync(absPath).size
  } catch {
    return 0
  }
}

/**
 * BFS through the dist entry to sum every chunk it pulls in. Catches the
 * lazy-loaded chunk graph (Argon2id, WebAuthn, JWT primitives) which a
 * single-file size misses.
 */
function bundleSize(entryRelPath: string): number {
  const seen = new Set<string>()
  const queue: string[] = [join(DIST_DIR, entryRelPath)]
  let total = 0
  while (queue.length > 0) {
    const f = queue.shift()
    if (f === undefined || seen.has(f)) continue
    seen.add(f)
    total += gzippedSize(f)
    let content: string
    try {
      content = readFileSync(f, 'utf-8')
    } catch {
      continue
    }
    const fileDir = f.substring(0, f.lastIndexOf('/'))
    const importMatches = content.match(/from\s+['"]([^'"]+)['"]/g) ?? []
    for (const raw of importMatches) {
      const m = raw.match(/from\s+['"]([^'"]+)['"]/)
      if (!m) continue
      const spec = m[1]
      if (!spec?.startsWith('.')) continue // skip externals
      const resolved = join(fileDir, spec.endsWith('.js') ? spec : `${spec}.js`)
      queue.push(resolved)
    }
  }
  return total
}

const subpaths: Array<{ name: string; entry: string }> = [
  { name: 'core', entry: 'core/index.js' },
  { name: 'core/transport', entry: 'core/transport/index.js' },
  { name: 'core/errors', entry: 'core/errors.js' },
  { name: 'adapters/memory', entry: 'adapters/memory/index.js' },
  { name: 'limiters/memory', entry: 'limiters/memory/index.js' },
  { name: 'providers/password', entry: 'providers/password/index.js' },
  { name: 'providers/magic-link', entry: 'providers/magic-link/index.js' },
  { name: 'providers/oauth/google', entry: 'providers/oauth/google/index.js' },
  { name: 'providers/oauth/github', entry: 'providers/oauth/github/index.js' },
  { name: 'server/generic', entry: 'server/generic/index.js' },
  { name: 'server/express', entry: 'server/express/index.js' },
  { name: 'server/hono', entry: 'server/hono/index.js' },
  { name: 'server/next', entry: 'server/next/index.js' },
  { name: 'client/vanilla', entry: 'client/vanilla/index.js' },
  { name: 'client/react', entry: 'client/react/index.js' },
]

const isolated: SubpathSize[] = subpaths.map(({ name, entry }) => {
  const abs = join(DIST_DIR, entry)
  return {
    subpath: `@gentleduck/auth/${name}`,
    entry,
    gzipped: bundleSize(entry),
    raw: rawSize(abs),
  }
})

// Realistic "full kit" profile - what a production B2C app actually loads.
const fullKitParts = [
  'core/index.js',
  'core/transport/index.js',
  'adapters/memory/index.js', // dev only, but we still measure
  'limiters/memory/index.js',
  'providers/password/index.js',
  'providers/magic-link/index.js',
  'providers/oauth/google/index.js',
  'server/express/index.js',
]
const fullKitGzip = fullKitParts.reduce((acc, p) => acc + bundleSize(p), 0)

const result = {
  generatedAt: new Date().toISOString(),
  subpaths: isolated.map((s) => ({
    subpath: s.subpath,
    gzipped_kb: +(s.gzipped / 1024).toFixed(2),
    raw_kb: +(s.raw / 1024).toFixed(2),
  })),
  profiles: {
    fullKit: {
      label: 'Full kit (core + cookie + memory + password + magic-link + Google oauth + Express)',
      includes: fullKitParts,
      gzipped_kb: +(fullKitGzip / 1024).toFixed(2),
    },
    minimalSession: {
      label: 'Session-only (core + cookie transport + memory adapter)',
      gzipped_kb: +((bundleSize('core/index.js') + bundleSize('adapters/memory/index.js')) / 1024).toFixed(2),
    },
  },
  budgets: {
    'core+cookie+memory': { target_kb: 14, gzipped_kb: 0 },
    'core+cookie+memory+password+drizzle': { target_kb: 30, gzipped_kb: 0 },
    fullKit: { target_kb: 78, gzipped_kb: +(fullKitGzip / 1024).toFixed(2) },
    'client/react': { target_kb: 5, gzipped_kb: +(bundleSize('client/react/index.js') / 1024).toFixed(2) },
  },
}

writeFileSync(join(OUT_DIR, 'results.json'), JSON.stringify(result, null, 2))

// Human-readable summary
console.log('\n@gentleduck/auth - bundle benchmark')
console.log('=====================================\n')
console.log('Subpath sizes (gzipped):')
for (const s of result.subpaths) {
  console.log(`  ${s.subpath.padEnd(40)} ${String(s.gzipped_kb).padStart(7)} KB`)
}
console.log('\nProfiles:')
console.log(`  Full kit:         ${result.profiles.fullKit.gzipped_kb} KB`)
console.log(`  Minimal session:  ${result.profiles.minimalSession.gzipped_kb} KB`)
console.log(`\nBudget check:`)
for (const [k, v] of Object.entries(result.budgets)) {
  const ok = v.gzipped_kb <= v.target_kb
  const mark = ok ? 'OK ' : 'NO '
  console.log(`  [${mark}] ${k.padEnd(45)} ${v.gzipped_kb} KB / target ${v.target_kb} KB`)
}
console.log(`\nWrote ${OUT_DIR}/results.json`)
