/** What the source loads, checked against what `package.json` declares, in both directions. */
import { globSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const PKG = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8'))
const PEERS: Record<string, string> = PKG.peerDependencies ?? {}
const DECLARED = new Set([...Object.keys(PKG.dependencies ?? {}), ...Object.keys(PEERS)])

/** Loaded from disk by path or built into the runtime, so they are not dependencies. */
const NOT_A_PACKAGE = /^[./]|^~\/|^node:/

const packageOf = (spec: string) => spec.split('/', spec.startsWith('@') ? 2 : 1).join('/')

/** Loaded on first use, through `import()` or a `createRequire` require. */
const lazy = new Set<string>()
const loaded = new Set<string>()
for (const file of globSync('src/**/*.ts', { cwd: ROOT })) {
  if (file.includes('__tests__') || file.startsWith('test/') || file.includes('/test/')) continue
  // Without comments, so a doc example's `from 'svelte/store'` does not count as loading svelte.
  const src = readFileSync(resolve(ROOT, file), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
  // Only a literal specifier: `await import(absolute)` is a runtime path, not a package.
  for (const m of src.matchAll(/\bimport\(\s*'([^']+)'(?:\s+as\s+string)?\s*\)|\b\w*[Rr]equire\(\s*'([^']+)'\s*\)/g)) {
    const spec = m[1] ?? m[2] ?? ''
    if (!NOT_A_PACKAGE.test(spec)) lazy.add(packageOf(spec))
  }
  for (const m of src.matchAll(/\bfrom\s+'([^']+)'|^\s*import\s+'([^']+)'/gm)) {
    const spec = m[1] ?? m[2] ?? ''
    if (!NOT_A_PACKAGE.test(spec)) loaded.add(packageOf(spec))
  }
}
for (const name of lazy) loaded.add(name)

describe('the packages the source loads', () => {
  it('are found, so a parse that matched nothing cannot read as a clean sweep', () => {
    expect(lazy).toContain('@simplewebauthn/server')
    expect(lazy).toContain('pg')
    expect(loaded).toContain('@nestjs/common')
  })

  it('are each a dependency or a peer', () => {
    expect([...loaded].filter((name) => !DECLARED.has(name)).sort()).toEqual([])
  })

  it('are optional peers when loaded lazily', () => {
    const meta = PKG.peerDependenciesMeta ?? {}
    expect([...lazy].filter((name) => meta[name]?.optional !== true).sort()).toEqual([])
  })

  it('cover every peer, so none is declared for nothing', () => {
    expect(Object.keys(PEERS).filter((name) => !loaded.has(name))).toEqual([])
  })

  it('are the names the install hints tell the user to install', () => {
    const wrong: string[] = []
    for (const file of globSync('src/**/*.ts', { cwd: ROOT })) {
      if (file.includes('__tests__')) continue
      const src = readFileSync(resolve(ROOT, file), 'utf8')
      for (const m of src.matchAll(/`([^`]+)` peerDep/g)) {
        const named = m[1] ?? ''
        if (!(named in PEERS)) wrong.push(`${file}: ${named}`)
      }
    }
    expect(wrong).toEqual([])
  })
})
