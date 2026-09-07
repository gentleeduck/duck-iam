import { readFileSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * The suite is split across two commands: `bun run test` runs everything that
 * does not need docker, `bun run test:e2e` runs everything that does. The split
 * is expressed twice — once as a vitest `--exclude` glob and once as a vitest
 * positional filter — and those two are different matching languages. A glob
 * matches path patterns; a positional filter is a plain substring test against
 * the file path.
 *
 * That is exactly how a test file goes silently unrun: if the two expressions
 * ever stop being complements of each other, a file lands in the gap and no
 * command executes it, while both commands still report green. This test pins
 * the two halves to the on-disk truth so the gap cannot open unnoticed.
 */

const PKG_ROOT = resolve(__dirname, '..', '..')
const SRC = join(PKG_ROOT, 'src')

/** The suffix that means "this test boots a container". */
const E2E_SUFFIX = '.e2e.test.ts'
/** Any test file at all, e2e or not. */
const TEST_SUFFIX = '.test.ts'

async function collectTestFiles(dir: string, found: string[] = []): Promise<string[]> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue
      await collectTestFiles(full, found)
      continue
    }
    if (entry.name.endsWith(TEST_SUFFIX)) found.push(relative(PKG_ROOT, full))
  }
  return found
}

function readScripts(): Record<string, string> {
  const raw: unknown = JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8'))
  if (typeof raw !== 'object' || raw === null || !('scripts' in raw)) {
    throw new Error('package.json has no scripts block')
  }
  const { scripts } = raw
  if (typeof scripts !== 'object' || scripts === null) throw new Error('scripts is not an object')
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(scripts)) {
    if (typeof value === 'string') out[name] = value
  }
  return out
}

describe('the two test commands partition every test file', () => {
  it('names both commands', () => {
    const scripts = readScripts()
    expect(scripts.test).toBeDefined()
    expect(scripts['test:e2e']).toBeDefined()
  })

  it('`test` excludes exactly the e2e suffix', () => {
    // If this changes shape, the substring filter below has to change with it.
    expect(readScripts().test).toContain(`--exclude "**/*${E2E_SUFFIX}"`)
  })

  it('`test:e2e` selects by a substring that only e2e files contain', async () => {
    const filter = readScripts()['test:e2e']?.split(/\s+/).at(-1)
    expect(filter).toBeTruthy()
    if (!filter) return

    const all = await collectTestFiles(SRC)
    const selected = all.filter((f) => f.includes(filter))
    const e2e = all.filter((f) => f.endsWith(E2E_SUFFIX))

    // Every e2e file is picked up, and nothing else is.
    expect([...selected].sort()).toEqual([...e2e].sort())
  })

  it('leaves no test file unrun by both commands', async () => {
    const filter = readScripts()['test:e2e']?.split(/\s+/).at(-1)
    if (!filter) throw new Error('no filter in test:e2e')

    const all = await collectTestFiles(SRC)
    const orphaned = all.filter((f) => f.endsWith(E2E_SUFFIX) && !f.includes(filter))
    expect(orphaned).toEqual([])
    expect(all.length).toBeGreaterThan(0)
  })

  it('runs no test file twice', async () => {
    const filter = readScripts()['test:e2e']?.split(/\s+/).at(-1)
    if (!filter) throw new Error('no filter in test:e2e')

    const all = await collectTestFiles(SRC)
    // `test` runs everything that is NOT the e2e suffix; `test:e2e` runs the
    // substring match. An overlap means a docker suite runs in the fast lane.
    const doubled = all.filter((f) => !f.endsWith(E2E_SUFFIX) && f.includes(filter))
    expect(doubled).toEqual([])
  })
})
