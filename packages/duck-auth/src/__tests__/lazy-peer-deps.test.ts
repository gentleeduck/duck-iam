/**
 * Every optional integration is loaded with `await import('name' as string)`, which hides it from the
 * bundler on purpose. It also hides it from `package.json`: five of these were imported at runtime,
 * told the user to install a "peerDep", and were declared in no dependency field at all.
 */
import { globSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const PKG = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8'))

/** Loaded from disk by path, not resolved from node_modules, so they are not dependencies. */
const NOT_A_PACKAGE = /^[./]|^~\//

const specifiers = new Set<string>()
for (const file of globSync('src/**/*.ts', { cwd: ROOT })) {
  if (file.includes('__tests__') || file.startsWith('test/') || file.includes('/test/')) continue
  const src = readFileSync(resolve(ROOT, file), 'utf8')
  // Only a literal specifier: `await import(absolute)` is a runtime path, not a package.
  for (const m of src.matchAll(/\bimport\(\s*'([^']+)'(?:\s+as\s+string)?\s*\)/g)) {
    const spec = m[1] ?? ''
    if (!NOT_A_PACKAGE.test(spec)) specifiers.add(spec)
  }
}

describe('packages loaded by dynamic import', () => {
  it('finds them, so a parse that matched nothing cannot read as a clean sweep', () => {
    expect(specifiers.size).toBeGreaterThan(5)
    expect(specifiers.has('@simplewebauthn/server')).toBe(true)
  })

  it('declares every one as an optional peer dependency', () => {
    const peers = PKG.peerDependencies ?? {}
    const meta = PKG.peerDependenciesMeta ?? {}
    const undeclared = [...specifiers].filter((s) => !(s in peers)).sort()
    expect(undeclared).toEqual([])
    const notOptional = [...specifiers].filter((s) => meta[s]?.optional !== true).sort()
    expect(notOptional).toEqual([])
  })

  it('tells the user to install the same name it imports', () => {
    // The install hint is the only contract a consumer sees at runtime, so it has to name a real package.
    const wrong: string[] = []
    for (const file of globSync('src/**/*.ts', { cwd: ROOT })) {
      if (file.includes('__tests__')) continue
      const src = readFileSync(resolve(ROOT, file), 'utf8')
      for (const m of src.matchAll(/`([^`]+)` peerDep/g)) {
        const named = m[1] ?? ''
        if (!(named in (PKG.peerDependencies ?? {}))) wrong.push(`${file}: ${named}`)
      }
    }
    expect(wrong).toEqual([])
  })
})
