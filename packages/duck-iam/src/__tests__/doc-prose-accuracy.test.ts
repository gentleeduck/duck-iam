import { readFileSync } from 'node:fs'
import { glob } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { IAM_UNKNOWN_ACTION, IAM_UNKNOWN_RESOURCE } from '../server/generic'

// Pins doc prose to the code it describes, so drift fails a test instead of shipping.

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
  // `IamHono.IOptions` is real API; a bare `IamHono` in prose should be the framework name.
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
  // Nothing emits a `scope:role` composite, so the `@example` must not show one.
  it('scopedRolesApplied is documented as plain role IDs', () => {
    const types = readFileSync(join(PKG, 'src/core/explain/explain.types.ts'), 'utf8')
    expect(types).not.toContain("'org-a:admin'")
    const engine = readFileSync(join(PKG, 'src/core/engine/engine.ts'), 'utf8')
    // The derivation the doc now describes.
    expect(engine).toContain(
      'const scopedRolesApplied = enrichedSubject.roles.filter((r) => !originalRoles.includes(r))',
    )
  })

  // An over-limit config warns and falls back to the interpreter; it does not make `preload()` throw.
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
    // The replaced claim: a bad deploy no longer fails to start.
    expect(faq).not.toContain('a bad deploy fails to start')
  })

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
  it('the README bench claim matches its own comparison table', () => {
    const readme = read('packages/duck-iam/README.md')
    const m = /Benchmarked against (\d+) other JS authorization libraries/.exec(readme)
    expect(m).not.toBeNull()

    const table = readme.slice(readme.indexOf('**Rule-matching only**'))
    const rows = [...table.slice(0, table.indexOf('\n\n**')).matchAll(/^\| ([^|]+?) \| ~[\d.]+[MK] \|/gm)]
    const competitors = rows.map((r) => r[1] ?? '').filter((n) => !n.includes('@gentleduck/iam'))
    expect(Number(m?.[1])).toBe(competitors.length)
  })

  it('the README does not describe development mode as interpreter-only', () => {
    const readme = read('packages/duck-iam/README.md')
    // The old development row of the mode table.
    expect(readme).not.toContain("`mode: 'development'` (interpreter)")
    // What replaced it.
    expect(readme).toContain('runs the same compiled table for the verdict')
    // 32 roles is where the fast path stops, not where the engine stops.
    expect(readme).not.toContain('hard cap: 32 per')
    expect(readme).toMatch(/falls back to the\s+interpreter/)
  })

  // `SCALING.md` lives only under the gitignored `tmp/`.
  it('the changelog cites no file that is not in the repo', () => {
    const changelog = read('packages/duck-iam/CHANGELOG.md')
    expect(changelog).not.toContain('SCALING.md')
  })

  // Some 5.0.0 names were removed outright, so prefixing imports alone does not upgrade.
  it('the 5.0.0 entry documents the removals, not just the renames', () => {
    const changelog = read('packages/duck-iam/CHANGELOG.md')
    const entry = changelog.slice(changelog.indexOf('## 5.0.0'), changelog.indexOf('## 4.0.0'))
    expect(entry).toContain('It is not a pure prefix rename')
    expect(entry).toContain('Removed, not renamed')
    for (const gone of ['createTypedAuthorize', 'PermissionMap', 'DefaultContext', 'validateRoles']) {
      expect(entry).toContain(gone)
    }
  })

  // Undocumented helpers get hand-rolled, and a hand-rolled `getAction` / `getResource` is bypassable.
  it('every request-derivation helper is documented', () => {
    // apps/duck-iam-docs was retired before this test existed; docs/reference/server.md is
    // the real, current source a developer integrating a new framework actually reads.
    const docs = read('packages/duck-iam/docs/reference/server.md')
    const mentioned = new Set([...docs.matchAll(/`([A-Za-z_][\w]*)`/g)].map((m) => m[1]))
    for (const name of [
      'IAM_UNKNOWN_ACTION',
      'IAM_UNKNOWN_RESOURCE',
      'iamActionForMethod',
      'iamDefaultResource',
      'iamNormalizePathname',
    ]) {
      expect(mentioned, `${name} is not documented in docs/reference/server.md`).toContain(name)
    }
    // Checked on the imported values, not source text: the constants read their value from `shared/reserved.ts`.
    expect(IAM_UNKNOWN_ACTION).toBe('unknown')
    expect(IAM_UNKNOWN_RESOURCE).toBe('unknown')
  })

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

describe('the engine reference keeps up with the config type', () => {
  /** Top-level `readonly x?:` members of `IConfig`; nested object members sit deeper and are skipped. */
  function configOptionNames(): string[] {
    const src = readFileSync(join(PKG, 'src/core/engine/engine.types.ts'), 'utf8')
    const start = src.indexOf('export interface IConfig')
    expect(start, 'IConfig not found in engine.types.ts').toBeGreaterThan(-1)
    const body = src.slice(start)
    const members = body.slice(0, body.indexOf('\n  }'))
    return [...members.matchAll(/^ {4}readonly (\w+)\??:/gm)].flatMap((m) => (m[1] === undefined ? [] : [m[1]]))
  }

  it('every IConfig option has a row in the config table', () => {
    const docs = read('packages/duck-iam/docs/reference/core-engine.md')
    const names = configOptionNames()
    expect(names.length).toBeGreaterThan(10)
    expect(names.filter((n) => !docs.includes(`| \`${n}\` |`))).toEqual([])
  })

  it('every option the constructor range-checks is listed among what it refuses', () => {
    const engine = readFileSync(join(PKG, 'src/core/engine/engine.ts'), 'utf8')
    const docs = read('packages/duck-iam/docs/reference/core-engine.md')
    // A numeric-bound guard carries `constraint:`; an enum-membership guard carries `allowed:` instead —
    // that's what distinguishes a "range-checked" option from the rest of IAM_ENGINE_INVALID_CONFIG's callers.
    const ranged = [...engine.matchAll(/throwIamError\('IAM_ENGINE_INVALID_CONFIG',\s*\{([^}]*)\}\)/g)]
      .map((m) => m[1] ?? '')
      .filter((body) => body.includes('constraint:'))
      .flatMap((body) => {
        const field = body.match(/field: '(\w+)'/)
        return field?.[1] === undefined ? [] : [field[1]]
      })
    // The table words some rows as a pair (`maxPolicies` / `maxRoles`), so the name is what must appear in it.
    const table = docs.slice(docs.indexOf('| Condition | Throws |'))
    const refusals = table.slice(0, table.indexOf('\n\n'))
    expect(ranged).toContain('hookTimeoutMs')
    expect(ranged.filter((n) => !refusals.includes(`\`${n}\``))).toEqual([])
  })
})

describe('the server reference states the audit hook timing the code has', () => {
  it('does not claim the hook can never block', () => {
    const docs = read('packages/duck-iam/docs/reference/server.md')
    expect(docs).not.toMatch(/can never block/)
    expect(docs).not.toMatch(/\*\*fire-and-forget\*\*/)
  })

  it('says the returned promise is not awaited and that synchronous work still delays the response', () => {
    const docs = read('packages/duck-iam/docs/reference/server.md')
    expect(docs).toMatch(/not awaited/)
    expect(docs).toMatch(/[Ss]ynchronous work does/)
  })

  it('the helper it describes still does not await the hook', () => {
    const src = readFileSync(join(PKG, 'src/server/generic/index.ts'), 'utf8')
    const fire = src.slice(src.indexOf('export function iamFireAdminMutation'))
    expect(fire.slice(0, fire.indexOf('\n}'))).not.toMatch(/await hook|await opts/)
  })
})
