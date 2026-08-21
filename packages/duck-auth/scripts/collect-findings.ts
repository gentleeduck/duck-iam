/**
 * Regenerate FINDINGS.md from the suite. Every test named `FINDING: ...` pins a
 * behaviour that was found and deliberately left unfixed, so the tests are the
 * source of truth and this file is derived. Run `bun run findings` after adding
 * or fixing one.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { Glob } from 'bun'

interface Finding {
  file: string
  line: number
  title: string
  why: string
}

const ROOT = join(import.meta.dir, '..')
const TITLE = /^\s*(?:it|test|describe)(?:\.\w+)?\(\s*["'`]FINDING:\s*(.*?)["'`]\s*,/

function collect(): Finding[] {
  const found: Finding[] = []
  for (const path of new Glob('src/**/*.test.ts').scanSync(ROOT)) {
    const lines = readFileSync(join(ROOT, path), 'utf8').split('\n')
    lines.forEach((line, i) => {
      const title = TITLE.exec(line)?.[1]
      if (!title) return
      // The comment block directly under the title is the explanation.
      const why: string[] = []
      for (let j = i + 1; j < lines.length && lines[j]?.trim().startsWith('//'); j++) {
        why.push((lines[j] as string).trim().slice(2).trim())
      }
      found.push({ file: relative('.', path), line: i + 1, title, why: why.join(' ') })
    })
  }
  return found.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line)
}

function render(findings: Finding[]): string {
  const byFile = new Map<string, Finding[]>()
  for (const f of findings) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f])

  const out = [
    '# Findings',
    '',
    `${findings.length} behaviours found by the hardening pass and deliberately left unfixed.`,
    '',
    'Generated from the suite by `bun run findings`. Do not edit by hand.',
    '',
    'Each one is pinned by a test named `FINDING: ...` that asserts the behaviour **as it is today**,',
    'so the suite is green while the bug exists and turns red the moment it is fixed. Fixing a bug',
    'therefore means updating its pin in the same commit.',
    '',
    '---',
    '',
  ]
  for (const [file, group] of byFile) {
    out.push(`## \`${file}\``, '')
    for (const f of group) {
      out.push(`- **L${f.line} - ${f.title}**`)
      if (f.why) out.push(`  <br>${f.why}`)
    }
    out.push('')
  }
  return `${out.join('\n')}\n`
}

const findings = collect()
writeFileSync(join(ROOT, 'FINDINGS.md'), render(findings))
writeFileSync(join(ROOT, 'src/test/findings.json'), `${JSON.stringify(findings, null, 2)}\n`)
console.log(`findings: ${findings.length} across ${new Set(findings.map((f) => f.file)).size} files`)
