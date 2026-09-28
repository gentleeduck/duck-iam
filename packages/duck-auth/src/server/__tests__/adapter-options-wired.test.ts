/**
 * An option a host can set and no adapter ever reads is accepted, type-checked and silently ignored.
 * `mountHono`'s `cors` was one. Nothing else in the package can catch this: a field that is declared and
 * never read is valid TypeScript.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), '..')

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

/** The body of every `type ...Options = { ... }`, generic or intersected (`= Base & { ... }`) too,
 *  brace-matched so a nested object does not end it. */
function optionsBodies(src: string): { name: string; body: string }[] {
  const out: { name: string; body: string }[] = []
  for (const m of src.matchAll(
    /(?:export\s+)?type\s+([A-Za-z0-9_]*Options)(?:<[^>]*>)?\s*=\s*(?:[^{};=\n]*&\s*)?\{/g,
  )) {
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
    // One from a generic type and one from an intersection, the two shapes a plain `= {` match skips.
    expect(declared.has('getCaller')).toBe(true)
    expect(declared.has('headerName')).toBe(true)
  })

  it('reads every declared field', () => {
    const unread: string[] = []
    for (const [field, owner] of declared) {
      // A read is `.field` or a destructured `field,`/`field }` - never the `field:` that declares it.
      const read = new RegExp(`\\.${field}\\b|(?:\\{|,)\\s*${field}\\s*(?:,|\\}|=)`)
      if (!read.test(ALL_SOURCE)) unread.push(`${owner}.${field}`)
    }
    expect(unread).toEqual([])
  })
})
