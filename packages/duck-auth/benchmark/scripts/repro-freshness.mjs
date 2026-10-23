/**
 * Does better-auth's freshness gate refuse a session it should?
 *
 * The condition is not retyped here. It is sliced out of their source file by
 * text and evaluated, so if their bytes said something else the answer would
 * change with them. Takes the file and the 1-based line of the `if` as args.
 */
import { readFileSync } from 'node:fs'

const [file, lineArg, label] = process.argv.slice(2)
const lines = readFileSync(file, 'utf8').split('\n')
const ifLine = Number(lineArg)

// The three statements the gate is made of: read createdAt, scale freshAge, compare.
const block = lines.slice(ifLine - 3, ifLine).map((l) => l.trim())
if (!block[2].startsWith('if (')) {
  console.error(`expected an if at line ${ifLine}, found: ${block[2]}`)
  process.exit(2)
}
const condition = block[2].slice(block[2].indexOf('(') + 1, block[2].lastIndexOf(')'))

console.log(`\n### ${label}  (${file.split('/').slice(-1)[0]}:${ifLine})`)
for (const l of block) console.log(`    ${l}`)

// `refuses` is true when their code would throw, i.e. the session is NOT fresh.
const refuses = new Function(
  'session',
  'ctx',
  `${block[0]}\n${block[1]}\nreturn !!(${condition})`,
)

const ctx = { context: { sessionConfig: { freshAge: 60 * 60 } } } // 1 hour, their default
const cases = [
  ['a session created now', new Date().toISOString()],
  ['a session created 2 hours ago (stale, must refuse)', new Date(Date.now() - 2 * 3600_000).toISOString()],
  ['a session dated 1 hour in the FUTURE', new Date(Date.now() + 3600_000).toISOString()],
  ['a session dated 100 years in the future', new Date(Date.now() + 100 * 365 * 86400_000).toISOString()],
  ['an unparseable createdAt', 'not-a-date'],
  ['createdAt as an empty string', ''],
  ['createdAt null', null],
]

for (const [name, createdAt] of cases) {
  const session = { session: { createdAt } }
  let verdict
  try {
    verdict = refuses(session, ctx) ? 'REFUSED (fresh gate held)' : 'ACCEPTED as fresh'
  } catch (e) {
    verdict = `threw ${e.constructor.name}`
  }
  console.log(`  ${verdict.padEnd(26)} <- ${name}`)
}
