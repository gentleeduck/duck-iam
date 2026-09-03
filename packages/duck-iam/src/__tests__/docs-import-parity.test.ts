import { readFileSync } from 'node:fs'
import { glob } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Round 2's J findings were, almost without exception, the same defect: a doc
 * page naming a symbol the package does not export. `nestAccessGuard`,
 * `createEngineProvider`, `generatePermissionMap`, `createTypedAuthorize`,
 * `MemoryAdapter`, `PermissionMap`, `IamRedisInvalidator`-as-a-class - nine of
 * them across the guides and the example app, every one of them a first-run
 * failure for whoever copied the snippet.
 *
 * They accumulated because nothing checked. The 5.0.0 `Iam*` rename touched the
 * source and the tests; the prose was invisible to both. This test makes the
 * prose visible: every `import { … } from '@gentleduck/iam[/subpath]'` in a
 * markdown or MDX code fence must name a real export of a real subpath.
 *
 * It reads the *source* barrels rather than `dist/`, so it runs without a build
 * and fails the moment a rename lands - not at the next release.
 */

const ROOT = join(import.meta.dirname, '../..')
const REPO = join(ROOT, '../..')

/** Doc trees that ship to readers. Anything here is a promise to somebody. */
const DOC_GLOBS = [
  'packages/duck-iam/README.md',
  'packages/duck-iam/FAQ.md',
  'guides/**/*.md',
  'apps/duck-iam-docs/content/**/*.mdx',
  'examples/**/README.md',
  // The example app's *source*, not just its README. Six of round 2's nine
  // dead imports were here - it is the "does this work end to end" reference,
  // and it did not build against the package it demonstrates.
  'examples/**/*.ts',
  'examples/**/*.tsx',
] as const

/**
 * `@gentleduck/iam/x/y` -> the source barrel implementing it. Derived from
 * `package.json#exports` so a new subpath cannot be documented before it is
 * exported, and `package-exports-parity.test.ts` already holds `exports`
 * against the build.
 */
function subpathToSource(): Map<string, string> {
  const raw: unknown = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  if (typeof raw !== 'object' || raw === null || !('exports' in raw)) {
    throw new Error('package.json has no exports map')
  }
  const exp: unknown = raw.exports
  if (typeof exp !== 'object' || exp === null) throw new Error('exports is not an object')

  const out = new Map<string, string>()
  for (const key of Object.keys(exp)) {
    const specifier = key === '.' ? '@gentleduck/iam' : `@gentleduck/iam/${key.slice(2)}`
    const dir = key === '.' ? 'src' : `src/${key.slice(2)}`
    out.set(specifier, join(ROOT, dir, 'index.ts'))
  }
  return out
}

/**
 * Names a barrel makes reachable, following `export * from './x'` one hop at a
 * time. Deliberately syntactic: importing the modules would pull `react`,
 * `vue`, `ioredis` and every driver into the test process, and the question
 * here is only "is this name spelled somewhere reachable".
 */
function exportedNames(entry: string, seen = new Set<string>()): Set<string> {
  const names = new Set<string>()
  if (seen.has(entry)) return names
  seen.add(entry)

  let src: string
  try {
    src = readFileSync(entry, 'utf8')
  } catch {
    return names
  }

  // `export function foo`, `export const foo`, `export class Foo`,
  // `export interface IFoo`, `export type Foo`, `export namespace Foo`
  for (const m of src.matchAll(
    /^export\s+(?:declare\s+)?(?:async\s+)?(?:function|const|let|var|class|interface|type|enum|namespace)\s+([A-Za-z_$][\w$]*)/gm,
  )) {
    if (m[1] !== undefined) names.add(m[1])
  }

  // `export { a, b as c } from './x'` and bare `export { a, b }`
  for (const m of src.matchAll(/^export\s+(?:type\s+)?\{([^}]*)\}/gm)) {
    for (const part of (m[1] ?? '').split(',')) {
      const alias = part.trim().split(/\s+as\s+/)
      const name = (alias[1] ?? alias[0] ?? '').trim().replace(/^type\s+/, '')
      if (name !== '') names.add(name)
    }
  }

  // `export * from './x'` - recurse into the re-exported barrel.
  for (const m of src.matchAll(/^export\s+\*\s+from\s+['"](\.[^'"]*)['"]/gm)) {
    const rel = m[1]
    if (rel === undefined) continue
    const base = join(entry, '..', rel)
    for (const candidate of [`${base}.ts`, join(base, 'index.ts')]) {
      for (const n of exportedNames(candidate, seen)) names.add(n)
    }
  }

  return names
}

interface IDocImport {
  readonly file: string
  readonly line: number
  readonly specifier: string
  readonly names: readonly string[]
}

/**
 * Only value/type imports with a named clause. A bare `import '…'` or a
 * default import names nothing to check.
 */
function collectDocImports(file: string): IDocImport[] {
  const text = readFileSync(file, 'utf8')
  const out: IDocImport[] = []
  const lines = text.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ''
    const m = /^\s*import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+['"](@gentleduck\/iam[^'"]*)['"]/.exec(line)
    if (m === null) continue
    const names = (m[1] ?? '')
      .split(',')
      .map((p) => {
        const alias = p.trim().split(/\s+as\s+/)
        return (alias[0] ?? '').trim().replace(/^type\s+/, '')
      })
      .filter((n) => n !== '')
    const specifier = m[2]
    if (specifier === undefined || names.length === 0) continue
    out.push({ file: file.slice(REPO.length + 1), line: i + 1, names, specifier })
  }
  return out
}

/**
 * Only the code inside fences. Prose *about* a wrong shape ("there is no
 * `result.ok`") is the fix, not the defect, and must not trip the check.
 */
function codeFences(text: string): string {
  const out: string[] = []
  let inside = false
  for (const line of text.split('\n')) {
    if (/^\s*```/.test(line)) {
      inside = !inside
      continue
    }
    if (inside) out.push(line)
  }
  return out.join('\n')
}

/**
 * The shape checks below describe duck-iam's types. `guides/duck-auth-setup.md`
 * documents a different package whose validators legitimately return `ok`, so
 * it is not in scope for them.
 */
function isIamDoc(file: string): boolean {
  return !file.includes('duck-auth-setup.md')
}

async function allDocFiles(): Promise<string[]> {
  const files: string[] = []
  for (const pattern of DOC_GLOBS) {
    for await (const f of glob(pattern, { cwd: REPO })) files.push(join(REPO, f))
  }
  return files.sort()
}

const SUBPATHS = subpathToSource()
const NAMES = new Map<string, Set<string>>()
for (const [specifier, entry] of SUBPATHS) NAMES.set(specifier, exportedNames(entry))

describe('documented imports resolve', () => {
  it('every documented `@gentleduck/iam` subpath is a real export entry', async () => {
    const bad: string[] = []
    for (const file of await allDocFiles()) {
      for (const imp of collectDocImports(file)) {
        if (!SUBPATHS.has(imp.specifier)) bad.push(`${imp.file}:${imp.line} -> ${imp.specifier}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('every symbol a doc imports is exported by the subpath it imports from', async () => {
    const bad: string[] = []
    for (const file of await allDocFiles()) {
      for (const imp of collectDocImports(file)) {
        const known = NAMES.get(imp.specifier)
        if (known === undefined) continue // reported by the subpath test above
        for (const name of imp.names) {
          if (!known.has(name)) bad.push(`${imp.file}:${imp.line} ${name} <- ${imp.specifier}`)
        }
      }
    }
    expect(bad).toEqual([])
  })

  it('the barrel reader actually finds names (guards against a silently-empty check)', () => {
    const root = NAMES.get('@gentleduck/iam')
    expect(root?.size ?? 0).toBeGreaterThan(50)
    expect(root).toContain('IamEngine')
    expect(root).toContain('iamBuildPermissionKey')
  })

  it('the docs corpus is non-empty and does contain iam imports', async () => {
    const files = await allDocFiles()
    expect(files.length).toBeGreaterThan(3)
    const total = files.reduce((n, f) => n + collectDocImports(f).length, 0)
    expect(total).toBeGreaterThan(10)
  })

  /**
   * The other half of round 2's J findings were not dead imports but dead
   * *shapes*: `decision.reasons`, `trace.matchedPolicies`, `result.ok`,
   * `admin.listAssignments`, `permissions()` returning an array. Each one reads
   * `undefined` at runtime and fails silently - `if (!result.ok)` fires on every
   * valid policy, and nobody notices until an audit.
   *
   * An import checker cannot see these, so they are pinned as phrases. Each
   * entry names the real shape so a future reader knows what to write instead.
   */
  it('no doc page describes a shape the code does not return', async () => {
    const DEAD_SHAPES: readonly (readonly [string, string])[] = [
      ['decision.reasons', 'IDecision has singular `reason`'],
      ['decision.trace', 'IDecision has no trace - call explain()'],
      ['trace.matchedPolicies', 'IResult exposes `policies`'],
      ['trace.allowed', 'the outcome is `trace.decision.allowed`'],
      ['result.ok', 'IamValidate.IResult is { valid, issues }'],
      ['result.errors', 'IamValidate.IResult is { valid, issues }'],
      ['roleResult.ok', 'IamValidate.IResult is { valid, issues }'],
      ['admin.listAssignments', 'read grants from the adapter'],
      ['results[0].allowed', 'permissions() returns a keyed map, not an array'],
      ['drizzle/schema/', 'the subpaths are adapters/drizzle/{pg,mysql,sqlite}'],
      ['new IamRedisInvalidator', 'createIamRedisInvalidator is a factory'],
    ]
    const bad: string[] = []
    for (const file of (await allDocFiles()).filter(isIamDoc)) {
      const code = codeFences(readFileSync(file, 'utf8'))
      const rel = file.slice(REPO.length + 1)
      for (const [phrase, instead] of DEAD_SHAPES) {
        if (code.includes(phrase)) bad.push(`${rel}: "${phrase}" - ${instead}`)
      }
    }
    expect(bad).toEqual([])
  })

  /**
   * `withIamAccess` made `opts.getUserId` mandatory in round 1 - deriving
   * identity from a request header is spoofable. Both the README snippet and
   * the JSDoc `@example` kept the four-argument form, so the single
   * most-copied Next.js snippet in the package threw on first run.
   */
  it('every documented withIamAccess call passes getUserId', async () => {
    const sources = [...(await allDocFiles()), join(ROOT, 'src/server/next/index.ts')]
    const bad: string[] = []
    for (const file of sources) {
      const text = readFileSync(file, 'utf8')
      const rel = file.slice(REPO.length + 1)
      // Strip JSDoc gutters first: inside `/** … */` every line of the
      // `@example` is prefixed with ` * `, which no `\s*` will match, so the
      // shipped JSDoc example would silently never be checked.
      const flat = text.replace(/^\s*\*[ \t]?/gm, '')
      // Requires a real first argument: `withIamAccess()` appears in prose as a
      // bare mention and is not a call site.
      for (const m of flat.matchAll(/withIamAccess\(\s*[A-Za-z_$][\s\S]{0,400}?\n\s*(?:\)|```)/g)) {
        const call = m[0]
        if (!call.includes('getUserId')) bad.push(`${rel}: withIamAccess(...) with no getUserId`)
      }
    }
    expect(bad).toEqual([])
  })

  /**
   * `allowFailOpen` is checked before mode is consulted at all
   * (`engine.ts:193`), so scoping it to production in prose understates it: a
   * developer reading that expects `defaultEffect: 'allow'` to work unguarded
   * in development, and gets a constructor throw.
   */
  it('no doc scopes the allowFailOpen requirement to production', async () => {
    const bad: string[] = []
    for (const file of await allDocFiles()) {
      const text = readFileSync(file, 'utf8')
      const rel = file.slice(REPO.length + 1)
      for (const line of text.split('\n')) {
        if (!line.includes('allowFailOpen')) continue
        if (/required to combine .*production/.test(line)) bad.push(`${rel}: ${line.trim()}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('the removed 5.0.0 names stay removed from the docs', async () => {
    // Every one of these was live in a shipped doc page in round 2.
    const GONE = [
      'createTypedAuthorize',
      'createEngineProvider',
      'nestAccessGuard',
      'generatePermissionMap',
      'accessMiddleware',
      'adminRouter',
      'withAccess',
      'checkAccess',
      'createNextMiddleware',
      'MemoryAdapter',
      'DrizzleAdapter',
      'PrismaAdapter',
      'HttpAdapter',
    ]
    const bad: string[] = []
    for (const file of await allDocFiles()) {
      for (const imp of collectDocImports(file)) {
        for (const name of imp.names) {
          if (GONE.includes(name)) bad.push(`${imp.file}:${imp.line} ${name}`)
        }
      }
    }
    expect(bad).toEqual([])
  })
})
