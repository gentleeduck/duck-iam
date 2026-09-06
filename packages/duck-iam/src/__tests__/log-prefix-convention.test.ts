import { readFileSync } from 'node:fs'
import { glob } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Every message this package writes to a console, or throws, is tagged
 * `[@gentleduck/iam:<module>]`. The module segment is the whole point: these
 * strings surface in a consumer's aggregated logs, where "something in
 * @gentleduck/iam threw about a missing `authorize` callback" is not an
 * actionable line - four different server integrations raise that same
 * sentence, and the tag is what says which one.
 *
 * Seven bare `[@gentleduck/iam]` prefixes had accumulated, all of them in
 * `src/server/**`, i.e. exactly where the ambiguity bites.
 */

const ROOT = join(import.meta.dirname, '../..')

async function sourceFiles(): Promise<string[]> {
  const out: string[] = []
  for await (const entry of glob('src/**/*.{ts,tsx}', { cwd: ROOT })) {
    if (entry.includes('__tests__') || entry.includes('/test/')) continue
    out.push(entry)
  }
  return out
}

describe('every log prefix names its module', () => {
  it('scans the source tree', async () => {
    // Control: a glob that matched nothing would make the assertion below pass.
    expect((await sourceFiles()).length).toBeGreaterThan(50)
  })

  it('uses no bare `[@gentleduck/iam]` tag', async () => {
    const offenders: string[] = []
    for (const file of await sourceFiles()) {
      const text = readFileSync(join(ROOT, file), 'utf8')
      text.split('\n').forEach((line, i) => {
        if (line.includes('[@gentleduck/iam]')) offenders.push(`${file}:${i + 1}`)
      })
    }
    expect(offenders).toEqual([])
  })

  it('still emits tagged messages, so the check is not vacuous', async () => {
    let tagged = 0
    for (const file of await sourceFiles()) {
      tagged += readFileSync(join(ROOT, file), 'utf8').split('[@gentleduck/iam:').length - 1
    }
    expect(tagged).toBeGreaterThan(80)
  })
})
