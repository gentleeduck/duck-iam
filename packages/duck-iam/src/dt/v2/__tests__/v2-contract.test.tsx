import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// Guards the `v2/` exclusion in `dt/__tests__/dt-selfcontained.test.tsx`: v2 exists, imports duck-ui,
// sits outside v1's sweep, and uses no part of v1's styling layer.
const v2Dir = dirname(dirname(fileURLToPath(import.meta.url)))
const dtDir = dirname(v2Dir)

/** Every `.ts`/`.tsx` under a directory, tests excluded, as `[relative path, source]`. */
function sourcesUnder(root: string, skipDirs: readonly string[] = []): [string, string][] {
  const out: [string, string][] = []
  const walk = (dir: string, prefix: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === '__tests__') continue
      if (entry.isDirectory() && prefix === '' && skipDirs.includes(entry.name)) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) walk(full, `${prefix}${entry.name}/`)
      else if (/\.tsx?$/.test(entry.name)) out.push([`${prefix}${entry.name}`, readFileSync(full, 'utf8')])
    }
  }
  walk(root, '')
  return out
}

const v2Sources = sourcesUnder(v2Dir)
const v1Sources = sourcesUnder(dtDir, ['v2'])

describe('v2 is a real, separate devtools built on duck-ui', () => {
  it('ships a set of modules of its own', () => {
    // Guard against an empty sweep passing every check below vacuously.
    expect(v2Sources.length, 'src/dt/v2 has no modules').toBeGreaterThanOrEqual(12)
  })

  it('imports duck-ui, which is exactly what v1 may not do', () => {
    const importers = v2Sources
      .filter(([, src]) => /^\s*import[^\n]*'@gentleduck\/registry-ui\//m.test(src))
      .map(([file]) => file)
    expect(
      importers.length,
      'no v2 module imports @gentleduck/registry-ui, so v2 is not a duck-ui build',
    ).toBeGreaterThanOrEqual(6)
  })

  it('uses duck-ui’s cn and lucide icons rather than reimplementing them', () => {
    const all = v2Sources.map(([, src]) => src).join('\n')
    expect(all).toMatch(/from '@gentleduck\/libs\/cn'/)
    expect(all).toMatch(/from 'lucide-react'/)
  })

  it('is not inside v1’s self-containment sweep', () => {
    expect(v1Sources.filter(([file]) => file.startsWith('v2/'))).toEqual([])
    // Guard against the line above passing because v1's sweep is empty too.
    expect(v1Sources.length).toBeGreaterThanOrEqual(18)
  })
})

/** Source with comments stripped, since comments may quote the very names the scans below look for. */
function codeOf(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1')
}

/** The string and template literals a module emits, quotes stripped. */
function literalsOf(src: string): string {
  // Strip comments first: a backtick span in a docblock would otherwise read as a template literal.
  const code = codeOf(src)
  return (code.match(/'[^'\n]*'|"[^"\n]*"|`[^`]*`/g) ?? []).map((literal) => literal.slice(1, -1)).join('\n')
}

/** The duck-ui subpaths v2 imports, e.g. `card` from `@gentleduck/registry-ui/card`. */
function duckUiModules(): Set<string> {
  const used = new Set<string>()
  for (const [, src] of v2Sources) {
    for (const match of src.matchAll(/from '@gentleduck\/registry-ui\/([a-z-]+)'/g)) {
      const name = match[1]
      if (name !== undefined) used.add(name)
    }
  }
  return used
}

/** Components v2 must take from duck-ui rather than rebuild, so the host theme can restyle them. */
const REQUIRED_DUCK_UI = [
  'alert',
  'avatar',
  'badge',
  'button',
  'button-group',
  'card',
  'empty',
  'field',
  'input',
  'input-group',
  'item',
  'kbd',
  'label',
  'progress',
  'scroll-area',
  'separator',
  'skeleton',
  'switch',
  'table',
  'tabs',
  'textarea',
  'tooltip',
] as const

describe('v2 is assembled from duck-ui rather than lookalikes', () => {
  it('uses each component duck-ui already ships for the job', () => {
    const used = duckUiModules()
    // Fail clearly on an empty scan rather than with a misleading per-component message.
    expect(used.size, 'the duck-ui import scan found nothing').toBeGreaterThanOrEqual(REQUIRED_DUCK_UI.length)
    for (const name of REQUIRED_DUCK_UI) {
      expect(used.has(name), `v2 no longer uses duck-ui's ${name}`).toBe(true)
    }
  })

  it('hand-rolls nothing duck-ui already ships', () => {
    // A raw `<table>` or hand-built progress bar looks right here but stops tracking the host theme.
    const offenders = v2Sources
      .filter(([, src]) => /<table[\s>]|<progress[\s>]|role="progressbar"/.test(codeOf(src)))
      .map(([file]) => file)
    expect(offenders, 'these v2 modules rebuild a duck-ui component instead of importing it').toEqual([])
  })
})

describe('v2 owns no part of v1’s styling layer', () => {
  it('reads a real set of literals', () => {
    // Guard against an empty literal scan passing the three checks below vacuously.
    const total = v2Sources.reduce((sum, [, src]) => sum + literalsOf(src).length, 0)
    expect(total, 'the literal scan found almost nothing').toBeGreaterThan(4000)
  })

  it('emits no iam-dt-* class', () => {
    // v2 never injects v1's stylesheet, so a borrowed class would have no rule.
    const offenders = v2Sources
      .filter(([, src]) => /(^|[\s"'`])iam-dt-[a-z0-9_-]+/.test(literalsOf(src)))
      .map(([file]) => file)
    expect(offenders, 'these v2 modules render a v1 class, which has no rule anywhere in a v2 build').toEqual([])
  })

  it('never injects v1’s stylesheet', () => {
    const offenders = v2Sources
      .filter(([, src]) => src.includes('useIamDevtoolsStyles(') || src.includes('ensureStylesInjected('))
      .map(([file]) => file)
    expect(offenders, 'v2 has no stylesheet to inject; styling comes from the host Tailwind build').toEqual([])
  })

  it('reads no --iam-dt-* token', () => {
    const offenders = v2Sources.filter(([, src]) => literalsOf(src).includes('--iam-dt-')).map(([file]) => file)
    expect(offenders, 'these v2 modules read a token only v1 declares').toEqual([])
  })
})

describe('both devtools are published', () => {
  const pkg: unknown = JSON.parse(readFileSync(join(dtDir, '../../package.json'), 'utf8'))

  function exportKeys(): string[] {
    if (typeof pkg !== 'object' || pkg === null) throw new Error('package.json is not an object')
    const exports: unknown = Reflect.get(pkg, 'exports')
    if (typeof exports !== 'object' || exports === null) throw new Error('package.json has no exports map')
    return Object.keys(exports)
  }

  it('exports ./dt and ./dt/v2 as separate subpaths', () => {
    // Separate subpaths let a consumer take v1 without bundling duck-ui.
    expect(exportKeys()).toContain('./dt')
    expect(exportKeys()).toContain('./dt/v2')
  })

  it('declares the three peers v2 needs, all optional', () => {
    if (typeof pkg !== 'object' || pkg === null) throw new Error('package.json is not an object')
    const peers: unknown = Reflect.get(pkg, 'peerDependencies')
    const meta: unknown = Reflect.get(pkg, 'peerDependenciesMeta')
    if (typeof peers !== 'object' || peers === null) throw new Error('no peerDependencies')
    if (typeof meta !== 'object' || meta === null) throw new Error('no peerDependenciesMeta')
    for (const name of ['@gentleduck/registry-ui', '@gentleduck/libs', 'lucide-react']) {
      expect(Object.hasOwn(peers, name), `${name} is not declared as a peer`).toBe(true)
      // Optional, so `./dt` (v1) installs without them.
      const entry: unknown = Reflect.get(meta, name)
      expect(typeof entry === 'object' && entry !== null && Reflect.get(entry, 'optional')).toBe(true)
    }
  })
})
