#!/usr/bin/env bun

/**
 *
 * Walks every src/**\/*.ts file (excluding __tests__) and ensures every
 * Idempotent: skips blocks that already have one.
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
for (const file of files) {
  const src = readFileSync(file, 'utf-8')
  // Regex captures every JSDoc block /** ... */ across multiline.
  const next = src.replace(/\/\*\*([\s\S]*?)\*\//g, (match, body: string) => {
    if (/@author\s+wildduck2/.test(body)) return match
    // Ignore single-line `/** foo */` blocks - too small for an author tag.
    if (!body.includes('\n')) return match
    // Inject AUTHOR before the closing */, preserving indent of the closing star.
    const closingIndentMatch = match.match(/(\n[ \t]*) \*\/$/)
    const indent = closingIndentMatch ? closingIndentMatch[1] : '\n'
    const tag = `${indent} *${indent} ${AUTHOR.trimStart()}`
    return match.replace(/(\s*\*\/)$/, `${tag}$1`)
  })
  if (next !== src) {
    writeFileSync(file, next)
    touched++
  }
}
console.log(`Touched ${touched} files`)
