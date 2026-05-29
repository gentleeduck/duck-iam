#!/usr/bin/env bun
/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 *
 * Injects a minimal JSDoc block before any `export function` or `export
 * class method` that lacks one. Idempotent: skips functions that already
 * have a `*\/` line directly preceding their `export` keyword.
 */

import { execSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'

const files = execSync(
  `find ${import.meta.dirname}/../src -name "*.ts" -not -path "*/__tests__/*" -not -path "*/__compliance__/*"`,
  { encoding: 'utf-8' },
)
  .trim()
  .split('\n')
  .filter(Boolean)

let touched = 0
let injected = 0

for (const file of files) {
  const src = readFileSync(file, 'utf-8')
  const lines = src.split('\n')
  const out: string[] = []

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ''
    const prev = out.length > 0 ? out[out.length - 1]! : ''
    const isExportFn = /^export (async )?function (\w+)/.test(line)
    if (isExportFn && !/\*\/$/.test(prev.trim())) {
      const match = line.match(/^export (?:async )?function (\w+)/)
      const name = match?.[1] ?? 'fn'
      // Compute indent (export is column 0 typically)
      const indent = line.match(/^\s*/)?.[0] ?? ''
      out.push(`${indent}/**`)
      out.push(`${indent} * \`${name}\`.`)
      out.push(`${indent} *`)
      out.push(`${indent} * @author wildduck2 <https://github.com/gentleeduck/duck-iam>`)
      out.push(`${indent} */`)
      injected++
    }
    out.push(line)
  }

  const next = out.join('\n')
  if (next !== src) {
    writeFileSync(file, next)
    touched++
  }
}

console.log(`Touched ${touched} files; injected ${injected} JSDoc blocks`)
