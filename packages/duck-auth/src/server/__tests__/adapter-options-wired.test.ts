/**
 * An option a host can set and no adapter ever reads is accepted, type-checked and silently ignored.
 * `mountHono`'s `cors` was one, and its own JSDoc claimed it mounted middleware. Nothing else in the
 * package can catch this: a field that is declared and never read is valid TypeScript.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/** Declared, read by nothing, and knowingly kept. Each entry is a decision someone has to unmake. */
const KNOWN_INERT = new Set(['cors'])

function sourcesUnder(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) {
      if (entry !== '__tests__') out.push(...sourcesUnder(p))
    } else if (entry.endsWith('.ts')) out.push(p)
  }
  return out
}

/** The body of every `type ...Options = { ... }`, brace-matched so a nested object does not end it. */
function optionsBodies(src: string): { name: string; body: string }[] {
  const out: { name: string; body: string }[] = []
  for (const m of src.matchAll(/(?:export\s+)?type\s+([A-Za-z0-9_]*Options)\s*=\s*\{/g)) {
    let depth = 1
    let i = (m.index ?? 0) + m[0].length
    const start = i
    while (i < src.length && depth > 0) {
      if (src[i] === '{') depth++
      else if (src[i] === '}') depth--
      i++
    }
    out.push({ body: src.slice(start, i - 1), name: m[1] ?? '' })
  }
  return out
}

/** Top-level field names only. Parens count toward the depth as well as braces, or the parameters of a
 *  callback field (`onAuthenticated?: (outcome: X, req: Y) => Z`) read as fields of the options type. */
function fieldNames(body: string): string[] {
  const names: string[] = []
  let depth = 0
  for (const line of body.split('\n')) {
    const trimmed = line.trim()
    if (depth === 0) {
      const m = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\??\s*:/)
      if (m?.[1]) names.push(m[1])
    }
    const open = (line.match(/[{(]/g) ?? []).length
    const close = (line.match(/[})]/g) ?? []).length
    depth += open - close
  }
  return names
}

const FILES = sourcesUnder(SERVER)
const ALL_SOURCE = FILES.map((f) => readFileSync(f, 'utf8')).join('\n')

describe('every adapter option a host can set is read by an adapter', () => {
  const declared = new Map<string, string>()
  for (const f of FILES) {
    for (const { name, body } of optionsBodies(readFileSync(f, 'utf8'))) {
      for (const field of fieldNames(body)) if (!declared.has(field)) declared.set(field, name)
    }
  }

  it('found the options types, so a silent parse failure cannot pass as a clean sweep', () => {
    expect(FILES.length).toBeGreaterThan(8)
    expect(declared.size).toBeGreaterThan(5)
    // The pair this guard was written for has to be in the list it checks.
    expect(declared.has('cors')).toBe(true)
  })

  it('reads every declared field, or says out loud that it does not', () => {
    const unread: string[] = []
    for (const [field, owner] of declared) {
      if (KNOWN_INERT.has(field)) continue
      // A read is `.field` or a destructured `field,`/`field }` - never the `field:` that declares it.
      const read = new RegExp(`\\.${field}\\b|(?:\\{|,)\\s*${field}\\s*(?:,|\\}|=)`)
      if (!read.test(ALL_SOURCE)) unread.push(`${owner}.${field}`)
    }
    expect(unread).toEqual([])
  })

  it('keeps the inert list honest: a field listed as inert must still be declared somewhere', () => {
    const stale = [...KNOWN_INERT].filter((f) => !declared.has(f))
    expect(stale).toEqual([])
  })
})
