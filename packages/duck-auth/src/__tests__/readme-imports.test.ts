/**
 * Every `@gentleduck/auth/...` import we hand a consumer has to resolve: the README examples, and the
 * `auth.ts` that `duck-auth init` writes. Both are strings, so no build anywhere type-checks them, and
 * a renamed export or a retired subpath rots there silently.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { __scaffoldTemplate } from '~/cli'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const README = readFileSync(resolve(ROOT, 'README.md'), 'utf8')
const EXPORTS: Record<string, unknown> = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8')).exports

/** `import { a, b } from '@gentleduck/auth/x'`, tolerating multi-line blocks and `// ...` comments. */
function importsIn(text: string, label: string): { where: string; subpath: string; symbols: string[] }[] {
  const out: { where: string; subpath: string; symbols: string[] }[] = []
  const re = /import\s*\{([\s\S]*?)\}\s*from\s*'@gentleduck\/auth([^']*)'/g
  for (const m of text.matchAll(re)) {
    const names = (m[1] ?? '')
      .replace(/\/\/[^\n]*/g, '')
      .split(',')
      .map(
        (s) =>
          s
            .trim()
            .replace(/^type\s+/, '')
            .split(/\s+as\s+/)[0]
            ?.trim() ?? '',
      )
      .filter((s) => s.length > 0)
    out.push({
      subpath: `.${m[2] ?? ''}`,
      symbols: names,
      where: `${label}:${text.slice(0, m.index).split('\n').length}`,
    })
  }
  return out
}

/** The source behind an `exports` key, both `x/index.ts` and `x.ts` layouts. */
function sourceFor(subpath: string): string | null {
  const rel = subpath === '.' ? 'index' : subpath.slice(2)
  for (const cand of [`src/${rel}/index.ts`, `src/${rel}.ts`]) {
    try {
      readFileSync(resolve(ROOT, cand), 'utf8')
      return cand
    } catch {}
  }
  return null
}

/** Exported names, following `export * from` one level, which is all the barrels use. */
function exportedNames(file: string, seen = new Set<string>()): Set<string> {
  const names = new Set<string>()
  if (seen.has(file)) return names
  seen.add(file)
  let src: string
  try {
    src = readFileSync(resolve(ROOT, file), 'utf8')
  } catch {
    return names
  }
  for (const m of src.matchAll(/export\s+(?:type\s+)?\{([\s\S]*?)\}(?:\s*from\s*'([^']+)')?/g)) {
    for (const raw of (m[1] ?? '').split(',')) {
      const part = raw.trim().replace(/^type\s+/, '')
      if (!part) continue
      const as = part.split(/\s+as\s+/)
      names.add((as[1] ?? as[0] ?? '').trim())
    }
  }
  for (const m of src.matchAll(
    /export\s+(?:declare\s+)?(?:abstract\s+)?(?:class|const|function|type|interface|namespace|enum)\s+([A-Za-z0-9_$]+)/g,
  )) {
    if (m[1]) names.add(m[1])
  }
  for (const m of src.matchAll(/export\s+\*\s+from\s+'([^']+)'/g)) {
    const spec = m[1]
    if (!spec) continue
    const base = spec.startsWith('~/') ? `src/${spec.slice(2)}` : resolve(dirname(file), spec).replace(`${ROOT}/`, '')
    for (const cand of [`${base}/index.ts`, `${base}.ts`]) {
      for (const n of exportedNames(cand, seen)) names.add(n)
    }
  }
  return names
}

describe('the imports we ship to consumers', () => {
  const imports = [
    ...importsIn(README, 'README.md'),
    ...importsIn(__scaffoldTemplate('quickstart'), 'init:quickstart'),
    ...importsIn(__scaffoldTemplate('production'), 'init:production'),
  ]

  it('finds the import examples', () => {
    expect(imports.length).toBeGreaterThan(10)
    // Both scaffold flavors reached the list, so a broken one cannot pass by being absent.
    expect(imports.some((i) => i.where.startsWith('init:quickstart'))).toBe(true)
    expect(imports.some((i) => i.where.startsWith('init:production'))).toBe(true)
  })

  it('names only subpaths the package exports', () => {
    const bad = imports.filter((i) => !(i.subpath in EXPORTS)).map((i) => `${i.where} ${i.subpath}`)
    expect(bad).toEqual([])
  })

  it('names only symbols those modules export', () => {
    const bad: string[] = []
    for (const imp of imports) {
      if (!(imp.subpath in EXPORTS)) continue
      const file = sourceFor(imp.subpath)
      if (!file) continue
      const names = exportedNames(file)
      for (const s of imp.symbols) {
        if (!names.has(s)) bad.push(`${imp.where} ${imp.subpath} -> ${s}`)
      }
    }
    expect(bad).toEqual([])
  })
})
