/**
 * Report optional keys that a `*.types.ts` declares and no implementation ever
 * reads.
 *
 * A key like that is a feature that does not exist: it type-checks at the call
 * site, the docs describe what it does, and nothing consumes it. Two shipped
 * ones were found this way - passkey's `excludeCredentials` (declared, never
 * populated, so re-registration minted duplicate credentials) and oauth's
 * `onFederationConflict` (declared on the impl's option type but not on the one
 * consumers pass, so every provider was hard-wired to `'reject'`).
 *
 * Reports, never fails. The output needs a human: a phantom brand and a field
 * a sibling package fills are both legitimately unread here.
 *
 * Run with `bun run dead-keys`.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const SRC = 'src'

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === '__tests__' || name === 'node_modules') continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (p.endsWith('.ts')) out.push(p)
  }
  return out
}

const files = walk(SRC)
const source = new Map(files.map((p) => [p, readFileSync(p, 'utf8')]))

/** key -> the `file:line` sites that declare it optional */
const declared = new Map<string, string[]>()
for (const [path, text] of source) {
  if (!path.endsWith('.types.ts')) continue
  text.split('\n').forEach((line, i) => {
    const m = /^\s{2,}([A-Za-z_][A-Za-z0-9_]*)\?:/.exec(line)
    if (m?.[1]) declared.set(m[1], [...(declared.get(m[1]) ?? []), `${path}:${i + 1}`])
  })
}

const dead: Array<{ key: string; sites: string[] }> = []
for (const [key, sites] of declared) {
  const pattern = new RegExp(`\\b${key}\\b`)
  const readers = [...source].filter(([p, text]) => !p.endsWith('.types.ts') && pattern.test(text))
  if (readers.length === 0) dead.push({ key, sites })
}

dead.sort((a, b) => a.key.localeCompare(b.key))
for (const { key, sites } of dead) console.log(`${key.padEnd(28)} ${sites.join(', ')}`)
console.log(`\n${dead.length} unread of ${declared.size} optional keys across ${files.length} files`)
