import { existsSync, readFileSync } from 'node:fs'
import { glob } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Everything below the package root lives behind a subpath import, so a module
 * reaches consumers only if it appears in **both** `tsdown.config.ts` (it gets
 * built) and `package.json#exports` (it can be imported). Neither file knows
 * about the other.
 *
 * Get it wrong in one direction and the subpath is dead on arrival -
 * `ERR_PACKAGE_PATH_NOT_EXPORTED` at the consumer, from a package whose own
 * test suite is green because tests import through relative paths. Get it wrong
 * in the other and `exports` points at a `dist/` file the build never emits.
 *
 * A round-3 finding claimed `./adapters/http` was missing from `exports`. It is
 * not, and was not - but nothing held the two lists together, so the claim was
 * one commit away from becoming true. This test is what holds them.
 */

const ROOT = join(import.meta.dirname, '../..')

function exportSubpaths(): string[] {
  const pkg: unknown = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  if (typeof pkg !== 'object' || pkg === null) throw new Error('package.json is not an object')
  const exports: unknown = Reflect.get(pkg, 'exports')
  if (typeof exports !== 'object' || exports === null) throw new Error('package.json has no exports map')
  return Object.keys(exports)
}

/** `'core/validate/index': 'src/core/validate/index.ts'` -> `['./core/validate', 'src/...']`. */
function buildEntries(): Array<{ source: string; subpath: string }> {
  const cfg = readFileSync(join(ROOT, 'tsdown.config.ts'), 'utf8')
  const entryBlock = cfg.slice(cfg.indexOf('entry: {'), cfg.indexOf('external: ['))
  const out: Array<{ source: string; subpath: string }> = []
  for (const [, quotedName, bareName, source] of entryBlock.matchAll(/(?:'([^']+)'|(\w+)):\s*'(src\/[^']+)'/g)) {
    // `index: 'src/index.ts'` is the one unquoted key.
    const name = quotedName ?? bareName
    if (name === undefined || source === undefined) throw new Error('unparsed tsdown entry')
    const trimmed = name.endsWith('/index') ? name.slice(0, -'/index'.length) : name
    out.push({ source, subpath: trimmed === 'index' ? '.' : `./${trimmed}` })
  }
  return out
}

describe('every built module is importable, and every import is built', () => {
  it('finds entries in both files', () => {
    // Control: a regex that silently matched nothing would make both set
    // comparisons below pass.
    expect(buildEntries().length).toBeGreaterThan(20)
    expect(exportSubpaths().length).toBeGreaterThan(20)
  })

  it('exports every subpath the build emits', () => {
    const exported = new Set(exportSubpaths())
    const unreachable = buildEntries()
      .map((e) => e.subpath)
      .filter((s) => !exported.has(s))
    expect(unreachable).toEqual([])
  })

  it('builds every subpath the exports map advertises', () => {
    const built = new Set(buildEntries().map((e) => e.subpath))
    expect(exportSubpaths().filter((s) => !built.has(s))).toEqual([])
  })

  it('points every build entry at a file that exists', () => {
    expect(buildEntries().filter((e) => !existsSync(join(ROOT, e.source)))).toEqual([])
  })
})

/**
 * `index.ts` under `src/core/**` says what a module publishes; it never says
 * what it does. Two of them had grown implementation - `core/explain/index.ts`
 * carried `iamEscapeHtml`, and `core/schema/index.ts` was 232 lines of JSON
 * Schema builders - which puts code in the one file a reader opens to find out
 * where the code is, and makes the barrel un-treeshakeable from its own
 * re-exports.
 *
 * The entrypoint `index.ts` files under `adapters/`, `server/`, `client/`,
 * `invalidators/`, `observability/` and `dt/` are deliberately different: each
 * is a tsdown entry and *is* the module.
 */
describe('core barrels re-export and nothing else', () => {
  async function coreBarrels(): Promise<string[]> {
    const out: string[] = []
    for await (const entry of glob('src/core/**/index.ts', { cwd: ROOT })) out.push(entry)
    return out
  }

  it('finds the barrels', async () => {
    expect((await coreBarrels()).length).toBeGreaterThan(10)
  })

  it('has no statement that is not a re-export', async () => {
    const offenders: string[] = []
    for (const file of await coreBarrels()) {
      const lines = readFileSync(join(ROOT, file), 'utf8').split('\n')
      let inBlockComment = false
      lines.forEach((raw, i) => {
        const line = raw.trim()
        if (inBlockComment) {
          if (line.includes('*/')) inBlockComment = false
          return
        }
        if (line === '' || line.startsWith('//') || line.startsWith('*')) return
        if (line.startsWith('/*')) {
          if (!line.includes('*/')) inBlockComment = true
          return
        }
        // A re-export is either a whole `export ... from '...'` statement or a
        // line inside one - a named-export list spans several lines.
        if (line.startsWith('export') || line.startsWith("} from '") || /^[\w{}, ]+,?$/.test(line)) return
        offenders.push(`${file}:${i + 1}: ${line}`)
      })
    }
    expect(offenders).toEqual([])
  })

  it('declares no function or class', async () => {
    const offenders: string[] = []
    for (const file of await coreBarrels()) {
      const text = readFileSync(join(ROOT, file), 'utf8')
      if (/^\s*(export )?(async )?(function|class|interface) /m.test(text)) offenders.push(file)
    }
    expect(offenders).toEqual([])
  })
})
