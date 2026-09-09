import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * The other half of `dt/__tests__/dt-selfcontained.test.tsx`.
 *
 * That file sweeps `src/dt` for imports of the optional peers and fails on
 * any it finds - and skips `v2/`, because v2 is built on duck-ui and importing
 * those peers is the whole point of it. An exclusion is only safe while
 * something asserts what it excludes, or it becomes the quiet hole where a v1
 * module goes to avoid the rule.
 *
 * So this file asserts the opposite contract from the other side: v2 exists,
 * v2 really does import duck-ui, v2 is really outside v1's sweep, and v2
 * carries no piece of v1's private styling layer. Delete v2 and these fail;
 * widen v1's exclusion and these fail; move a v1 module under `v2/` to dodge
 * the peer rule and the last check here catches it.
 */
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
    // Anti-vacuity for every check below: an empty tree satisfies a filter.
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
    // ...and v1 is still swept, so the line above is not passing because both
    // sides are empty.
    expect(v1Sources.length).toBeGreaterThanOrEqual(18)
  })
})

/**
 * The string and template literals a module actually emits, with their quotes
 * stripped.
 *
 * The checks below have to read these rather than the raw text. Both files
 * that *document* the v1/v2 split - `index.ts` and `lib/tone.ts` - name v1's
 * `iam-dt-*` classes and `--iam-dt-*` tokens in prose, correctly and on
 * purpose, and a raw-text sweep cannot tell that from a class being rendered.
 * It would have to be either satisfied by an accident of punctuation or
 * silenced by exempting the two files that explain the rule.
 */
function codeOf(src: string): string {
  // Comments go first, for every scan below. Docblocks in this directory
  // quote the very names the scans look for - v1's classes and tokens, and
  // the elements v2 is forbidden to hand-roll - correctly and on purpose. A
  // raw-text sweep cannot tell prose from markup, so it would have to be
  // either satisfied by an accident of punctuation or silenced by exempting
  // the files that explain the rule.
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1')
}

function literalsOf(src: string): string {
  // A backtick span in a docblock is indistinguishable from a template
  // literal once the comment markers are gone, hence `codeOf` first.
  const code = codeOf(src)
  return (code.match(/'[^'\n]*'|"[^"\n]*"|`[^`]*`/g) ?? []).map((literal) => literal.slice(1, -1)).join('\n')
}

/**
 * The duck-ui subpaths v2 imports, e.g. `card` from
 * `@gentleduck/registry-ui/card`.
 */
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

/**
 * The components v2 is required to take from duck-ui rather than rebuild.
 *
 * Not a wish list - each one replaced something hand-rolled, and each is a
 * shape a host theme is entitled to restyle. A `div` with a border is a card
 * only we know about; duck-ui's `Card` is a card the host can reach.
 */
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
    // Anti-vacuity: the loop below passes trivially if the scan found nothing
    // and every `has` is being asked of an empty set - which would fail, but
    // with a misleading message. This is the honest failure.
    expect(used.size, 'the duck-ui import scan found nothing').toBeGreaterThanOrEqual(REQUIRED_DUCK_UI.length)
    for (const name of REQUIRED_DUCK_UI) {
      expect(used.has(name), `v2 no longer uses duck-ui's ${name}`).toBe(true)
    }
  })

  it('hand-rolls nothing duck-ui already ships', () => {
    // A raw `<table>` or a hand-built progress bar renders fine and is exactly
    // the regression this guards: it looks right in the monorepo's theme and
    // stops tracking the host's the moment either changes.
    const offenders = v2Sources
      .filter(([, src]) => /<table[\s>]|<progress[\s>]|role="progressbar"/.test(codeOf(src)))
      .map(([file]) => file)
    expect(offenders, 'these v2 modules rebuild a duck-ui component instead of importing it').toEqual([])
  })
})

describe('v2 owns no part of v1’s styling layer', () => {
  it('reads a real set of literals', () => {
    // Anti-vacuity for all three checks below: a regex that matched nothing
    // would make every one of them pass.
    const total = v2Sources.reduce((sum, [, src]) => sum + literalsOf(src).length, 0)
    expect(total, 'the literal scan found almost nothing').toBeGreaterThan(4000)
  })

  it('emits no iam-dt-* class', () => {
    // v1's classes only exist while v1's stylesheet is injected, and v2 never
    // injects it. One borrowed class would render as nothing at all.
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
    // Separate subpaths are what let a consumer take v1 without pulling
    // duck-ui into their bundle, which is the reason both exist.
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
      // Optional, because `./dt` (v1) must keep installing without them. A
      // required peer here would make v1 unusable for the consumers it exists
      // for, and npm would warn on every install.
      const entry: unknown = Reflect.get(meta, name)
      expect(typeof entry === 'object' && entry !== null && Reflect.get(entry, 'optional')).toBe(true)
    }
  })
})
