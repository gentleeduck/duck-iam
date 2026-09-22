import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Relative links in shipped markdown must point at something `package.json#files` also ships: a checkout resolves
// every link, an installed tarball may not. Absolute URLs and fragments are out of scope.

const PKG_ROOT = join(__dirname, '..', '..')

/** The `files` globs, reduced to the top-level names they admit. */
function shippedRoots(): string[] {
  const parsed: unknown = JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8'))
  const files = parsed !== null && typeof parsed === 'object' ? Reflect.get(parsed, 'files') : undefined
  if (!Array.isArray(files)) throw new Error('package.json has no `files` array')
  return files.filter((f): f is string => typeof f === 'string')
}

/** Relative markdown link targets, minus fragments and query strings. */
function relativeLinks(markdown: string): string[] {
  const out: string[] = []
  for (const m of markdown.matchAll(/\]\(([^)\s]+)\)/g)) {
    const raw = m[1]
    if (raw === undefined) continue
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith('#') || raw.startsWith('//')) continue
    const path = raw.split('#')[0]?.split('?')[0]
    if (path !== undefined && path.length > 0) out.push(path)
  }
  return out
}

/** Is `relPath` (relative to the package root) inside something `files` ships? */
function isShipped(relPath: string, roots: readonly string[]): boolean {
  const normalised = relPath.replace(/^\.\//, '')
  return roots.some((r) => normalised === r || normalised.startsWith(`${r}/`))
}

describe('the docs the README points at are the docs that ship', () => {
  const roots = shippedRoots()

  it('CONTROL: the README itself is shipped, so this test can find one', () => {
    expect(isShipped('README.md', roots)).toBe(true)
  })

  it('CONTROL: a path outside every shipped root is recognised as unshipped', () => {
    // Guards the matcher: a predicate answering `true` for everything would prove nothing.
    expect(isShipped('audit-iam/FIX-LOG.md', roots)).toBe(false)
  })

  it('every relative link in the README resolves to a file that ships', () => {
    const readme = readFileSync(join(PKG_ROOT, 'README.md'), 'utf8')
    const unshipped = relativeLinks(readme).filter((l) => !isShipped(l, roots))
    expect(unshipped).toEqual([])
  })

  it('every relative link in the README points at a file that exists', () => {
    const readme = readFileSync(join(PKG_ROOT, 'README.md'), 'utf8')
    const missing = relativeLinks(readme).filter((l) => !existsSync(join(PKG_ROOT, l)))
    expect(missing).toEqual([])
  })

  it('the reference index links only to pages that exist and ship', () => {
    const indexPath = join(PKG_ROOT, 'docs', 'reference', 'README.md')
    // Not skipped when absent: the README tells readers to start here.
    expect(existsSync(indexPath)).toBe(true)
    const index = readFileSync(indexPath, 'utf8')
    const bad = relativeLinks(index)
      .map((l) => join('docs', 'reference', l))
      .filter((abs) => !existsSync(join(PKG_ROOT, abs)) || !isShipped(abs.split('/').slice(0).join('/'), roots))
    expect(bad).toEqual([])
  })
})
