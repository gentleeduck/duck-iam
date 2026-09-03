import { readFileSync } from 'node:fs'
import { glob } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { IAM_UNKNOWN_ACTION, IAM_UNKNOWN_RESOURCE } from '../server/generic'

/**
 * Round 2's low-severity J findings were prose that had quietly stopped being
 * true. Individually cosmetic; collectively they are why the docs stopped being
 * trusted. Each block below pins one of them to the code it describes, so the
 * next drift fails a test instead of shipping.
 */

const PKG = join(import.meta.dirname, '../..')
const REPO = join(PKG, '../..')

function read(...parts: string[]): string {
  return readFileSync(join(REPO, ...parts), 'utf8')
}

async function sourceFiles(): Promise<string[]> {
  const out: string[] = []
  for await (const f of glob('**/*.ts?(x)', { cwd: join(PKG, 'src') })) {
    if (!f.includes('__tests__')) out.push(f)
  }
  return out.sort()
}

describe('JSDoc names third-party frameworks correctly', () => {
  /**
   * Round 1's rename script was a blanket find-and-replace, so it prefixed the
   * *frameworks* too: "a IamHono middleware function", "IamNest's
   * decorator-driven routing", "Wraps a IamNext.js App Router route handler".
   * It also produced a genuinely non-compiling `@example` in the Hono adapter:
   * `import { IamHono } from 'hono'` / `new IamHono()`.
   *
   * `IamHono.IOptions` and `export namespace IamHono` are real API and must
   * survive; only the bare prose mention is wrong. That is the distinction the
   * check encodes.
   */
  it('no bare Iam-prefixed framework name outside a namespace declaration', async () => {
    const bad: string[] = []
    for (const rel of await sourceFiles()) {
      const lines = readFileSync(join(PKG, 'src', rel), 'utf8').split('\n')
      for (const [i, line] of lines.entries()) {
        if (line.includes('export namespace')) continue
        // A bare framework name: not followed by `.` (a qualified type
        // reference) and not the head of a longer identifier.
        for (const m of line.matchAll(/\bIam(Hono|Express|Nest|Next)\b(?!\.)/g)) {
          bad.push(`src/${rel}:${i + 1} ${m[0]}`)
        }
      }
    }
    expect(bad).toEqual([])
  })

  it('the Hono admin-router example imports the real Hono class', () => {
    const src = readFileSync(join(PKG, 'src/server/hono/index.ts'), 'utf8')
    expect(src).toContain("import { Hono } from 'hono'")
    expect(src).toContain('const admin = new Hono()')
  })

  it('the scanner is not silently matching nothing', async () => {
    const files = await sourceFiles()
    expect(files.length).toBeGreaterThan(50)
    // The namespaces themselves still exist - proof the exclusion is load-bearing.
    const hono = readFileSync(join(PKG, 'src/server/hono/index.ts'), 'utf8')
    expect(hono).toContain('export namespace IamHono')
    expect(hono).toContain('IamHono.IOptions')
  })
})

describe('documented shapes match the code', () => {
  /**
   * `engine.ts` derives `scopedRolesApplied` as `enrichedSubject.roles` minus
   * `originalRoles` - plain role IDs. The `@example` showed `'org-a:admin'`, a
   * `scope:role` composite nothing in the package ever emits, so a reader
   * parsing on `:` gets nothing back and cannot tell whether that means "no
   * scoped roles" or "my parser is wrong".
   */
  it('scopedRolesApplied is documented as plain role IDs', () => {
    const types = readFileSync(join(PKG, 'src/core/explain/explain.types.ts'), 'utf8')
    expect(types).not.toContain("'org-a:admin'")
    const engine = readFileSync(join(PKG, 'src/core/engine/engine.ts'), 'utf8')
    // The derivation the doc now describes.
    expect(engine).toContain(
      'const scopedRolesApplied = enrichedSubject.roles.filter((r) => !originalRoles.includes(r))',
    )
  })

  /**
   * `ac70b714` made `preload()` build the compiled permission table, which is
   * what surfaces an over-32-role config at boot rather than on the first
   * request. Neither the JSDoc nor the FAQ said so.
   *
   * Two things have since changed and both are pinned here, because the FAQ
   * said the opposite of each until it was corrected by hand: the table is
   * built in *both* modes now, and an over-limit config no longer throws from
   * `preload()` - it warns, falls back to the interpreter, and is reported on
   * the health probe.
   */
  it('preload() is documented as building the compiled table in both modes', () => {
    const engine = readFileSync(join(PKG, 'src/core/engine/engine.ts'), 'utf8')
    // The behaviour...
    expect(engine).toContain('buildCompiledTable: () => this._getCompiledTable()')
    // ...and the docs for it, in both places a reader looks.
    const jsdoc = engine.slice(0, engine.indexOf('async preload('))
    expect(jsdoc.slice(-1400)).toContain('compiled permission table')
    const faq = read('packages/duck-iam/FAQ.md')
    expect(faq).toContain('It also builds the compiled permission table - in both modes')
    expect(faq).toContain('falls back to the interpreter')
    // The claim it replaced. A deploy that fails to start is exactly what no
    // longer happens, and a reader acting on it would plan for the wrong
    // failure mode.
    expect(faq).not.toContain('a bad deploy fails to start')
  })

  /**
   * `IResource.attributes` is required. Three doc sites omitted it, so the
   * snippet a reader copies does not typecheck.
   */
  it('IResource.attributes is still required, so no doc may omit it', () => {
    const request = readFileSync(join(PKG, 'src/core/types/request.ts'), 'utf8')
    // Not `attributes?:` - if this ever becomes optional the docs below are
    // free to drop it and this whole block should go.
    expect(request).toMatch(/readonly attributes: Readonly<IamPrimitives\.Attributes>/)

    const bad: string[] = []
    for (const doc of ['guides/duck-iam-setup.md', 'packages/duck-iam/README.md', 'packages/duck-iam/FAQ.md']) {
      const text = read(doc)
      for (const [i, line] of text.split('\n').entries()) {
        // A single-line resource literal with no `attributes` key.
        if (/\{\s*type: '[a-z]+'(,\s*id: [^,}]+)?\s*\}/.test(line) && !line.includes('attributes')) {
          bad.push(`${doc}:${i + 1} ${line.trim()}`)
        }
      }
    }
    expect(bad).toEqual([])
  })
})

describe('counts and cross-references stay true', () => {
  /**
   * The README said "6 JS authorization libraries" while its own table listed
   * five competitors plus duck-iam, and the FAQ said five. Derive the number
   * from the table so the two cannot disagree again.
   */
  it('the README bench claim matches its own comparison table', () => {
    const readme = read('packages/duck-iam/README.md')
    const m = /Benchmarked against (\d+) other JS authorization libraries/.exec(readme)
    expect(m).not.toBeNull()

    const table = readme.slice(readme.indexOf('**Rule-matching only**'))
    const rows = [...table.slice(0, table.indexOf('\n\n**')).matchAll(/^\| ([^|]+?) \| ~[\d.]+[MK] \|/gm)]
    const competitors = rows.map((r) => r[1] ?? '').filter((n) => !n.includes('@gentleduck/iam'))
    expect(Number(m?.[1])).toBe(competitors.length)
  })

  /**
   * Three README claims were true only while `mode: 'development'` ran the
   * interpreter alone. All three survived the architecture change unchanged and
   * had to be found by grep, which is the coverage gap this test closes.
   */
  it('the README does not describe development mode as interpreter-only', () => {
    const readme = read('packages/duck-iam/README.md')
    // The mode table's development row carried a `~155K` figure measured under
    // the old architecture, against a production row measured the same day.
    // Removed rather than re-measured: a fresh number from a different machine
    // and build is not comparable to the rest of the table.
    expect(readme).not.toContain("`mode: 'development'` (interpreter)")
    // What replaced it: the reason development is slower, stated as a ratio,
    // which is the part that *is* comparable within one run.
    expect(readme).toContain('runs the same compiled table for the verdict')
    // 32 roles is where the fast path stops, not where the engine stops.
    expect(readme).not.toContain('hard cap: 32 per')
    expect(readme).toMatch(/falls back to the\s+interpreter/)
  })

  /**
   * The 5.7.0 entry cited `SCALING.md` §8, which lives only under the
   * gitignored `tmp/`. A changelog that points at a file the reader cannot open
   * is worse than one that says nothing.
   */
  it('the changelog cites no file that is not in the repo', () => {
    const changelog = read('packages/duck-iam/CHANGELOG.md')
    expect(changelog).not.toContain('SCALING.md')
  })

  /**
   * The 5.0.0 entry called the break a pure prefix rename. Some names were
   * removed outright, and an upgrader mechanically prefixing imports hits those
   * with no migration table anywhere.
   */
  it('the 5.0.0 entry documents the removals, not just the renames', () => {
    const changelog = read('packages/duck-iam/CHANGELOG.md')
    const entry = changelog.slice(changelog.indexOf('## 5.0.0'), changelog.indexOf('## 4.0.0'))
    expect(entry).toContain('It is not a pure prefix rename')
    expect(entry).toContain('Removed, not renamed')
    for (const gone of ['createTypedAuthorize', 'PermissionMap', 'DefaultContext', 'validateRoles']) {
      expect(entry).toContain(gone)
    }
  })

  /**
   * The five request-derivation helpers were exported and documented nowhere,
   * which is what left readers hand-rolling the bypassable `getAction` /
   * `getResource` that round 1 removed.
   */
  it('every request-derivation helper is documented', () => {
    const mdx = read('apps/duck-iam-docs/content/docs/integrations/server.mdx')
    // A passing mention in prose is not documentation. Each helper needs its
    // own reference-table row *and* a place in the copyable import block -
    // otherwise a reader cannot find out what it does or where it comes from.
    // (Checking only `mdx.includes(name)` let a renamed table row pass, because
    // the old name still appeared in a nearby paragraph.)
    const tableRows = new Set([...mdx.matchAll(/^\| `([A-Za-z_][\w]*)` \|/gm)].map((m) => m[1]))
    // Any of the page's `import { … } from '…/server/generic'` blocks will do,
    // as long as one of them shows the whole set together.
    const importBlocks = [...mdx.matchAll(/import \{([^}]*)\} from '@gentleduck\/iam\/server\/generic'/g)].map(
      (m) => m[1] ?? '',
    )
    for (const name of [
      'IAM_UNKNOWN_ACTION',
      'IAM_UNKNOWN_RESOURCE',
      'iamActionForMethod',
      'iamDefaultResource',
      'iamNormalizePathname',
    ]) {
      expect(tableRows, `${name} has no reference-table row`).toContain(name)
      expect(
        importBlocks.some((b) => b.includes(name)),
        `${name} appears in no server/generic import block`,
      ).toBe(true)
    }
    // And they are still exported under those names, with the values the page
    // documents. Asserted on the imported values rather than on the text of the
    // source file: the constants now read their value from the reserved token
    // in `shared/reserved.ts` (a string sentinel could not carry the denial the
    // docs promised - `'*'` matches strings), and a substring match on the old
    // one-line literal called that a documentation failure when nothing the
    // page states had changed.
    expect(IAM_UNKNOWN_ACTION).toBe('unknown')
    expect(IAM_UNKNOWN_RESOURCE).toBe('unknown')
  })

  /**
   * The root README described the example app as "Next.js + Prisma". It is
   * Drizzle on bun-sqlite, with a NestJS API - so the one reader who picked it
   * because they use Prisma found the wrong thing.
   */
  it('the root README names the example app stack the example actually uses', () => {
    const row = read('README.md')
      .split('\n')
      .find((l) => l.includes('examples/blogduck') && l.includes('|'))
    expect(row).toBeDefined()
    expect(row).not.toContain('Prisma')
    expect(row).toContain('Drizzle')
    // Which is what the example imports.
    expect(read('examples/blogduck/packages/shared/src/access.ts')).toContain('IamDrizzleAdapter')
    expect(read('examples/blogduck/packages/shared/src/db.ts')).toContain('drizzle-orm/bun-sqlite')
  })
})
