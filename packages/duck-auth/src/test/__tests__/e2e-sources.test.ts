/** The e2e manifest against the tree it describes: a listed suite that is gone, an e2e suite nobody listed,
 *  or a source id with no entry leaves it unable to say where a case comes from. */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const MANIFEST: { sources: Record<string, unknown>; suites: { file: string; derivedFrom: string[] }[] } = JSON.parse(
  readFileSync(resolve(ROOT, 'src/test/e2e-sources.json'), 'utf8'),
)
const LISTED = MANIFEST.suites.map((s) => s.file)

describe('the e2e manifest', () => {
  it('lists no suite that is gone', () => {
    expect(LISTED.filter((f) => !existsSync(resolve(ROOT, f)))).toEqual([])
  })

  it('lists every e2e suite', () => {
    const suites = readdirSync(resolve(ROOT, 'src'), { encoding: 'utf8', recursive: true })
      .filter((p) => p.endsWith('.e2e.test.ts'))
      .map((p) => `src/${p}`)
    expect(suites.length).toBeGreaterThan(30)
    expect(suites.filter((f) => !LISTED.includes(f))).toEqual([])
  })

  it('defines every source a suite derives from, and none that nothing uses', () => {
    const used = new Set(MANIFEST.suites.flatMap((s) => s.derivedFrom))
    expect([...used].filter((id) => !(id in MANIFEST.sources))).toEqual([])
    expect(Object.keys(MANIFEST.sources).filter((id) => !used.has(id))).toEqual([])
  })
})
