#!/usr/bin/env node
// Converts typedoc-plugin-markdown's output (content/docs/api/generated/**/*.md) into
// .mdx with frontmatter, so it's picked up by the same Velite pipeline as the
// hand-written docs (which only globs *.mdx) once synced into @duck-ui.
//
// Filenames and relative link targets are kept exactly as typedoc emits them (minus the
// .md extension) because api/index.mdx already links to this tree that way
// (./generated/README, ./generated/functions/createIam, ...).
import { readFileSync, writeFileSync, unlinkSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = join(import.meta.dirname, '..', 'content', 'docs', 'api', 'generated')
const PKG_TITLE = '@gentleduck/iam'

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else if (entry.endsWith('.md')) out.push(p)
  }
  return out
}

// Strips markdown link/escape syntax down to plain text, for frontmatter fields that
// typedoc's raw prose can't carry as-is (YAML strings render literally, not as markdown).
function toPlainText(line) {
  return line
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // [text](link) -> text
    .replace(/\\([<>[\]])/g, '$1') // \< \> \[ \] -> literal
    .replace(/`/g, '')
    .trim()
}

// Drops the type parameter list: `Class: Foo<T extends ...>` reads as `Class: Foo`, inside the site's 99-char title cap.
// A heading that is only `<internal>` keeps it, or the page ends up with no title.
function unescapeTitle(line) {
  const plain = toPlainText(line.replace(/^#\s+/, ''))
  return plain.replace(/<.*>$/, '') || plain
}

function yamlString(value) {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function extractDescription(bodyLines) {
  let i = 0
  while (i < bodyLines.length) {
    const line = bodyLines[i]
    // Overloaded functions get one "## Call Signature" block per overload before the
    // shared description; skip the heading itself rather than bailing out on it.
    if (/^#{2,3}\s+Call Signature\s*$/.test(line.trim())) {
      i++
      continue
    }
    if (line.startsWith('##')) return null
    if (line.trim() === '' || line.startsWith('>') || line.startsWith('Defined in:')) {
      i++
      continue
    }
    // First prose line found - collect the paragraph until the next blank line.
    const para = []
    while (i < bodyLines.length && bodyLines[i].trim() !== '') {
      para.push(bodyLines[i])
      i++
    }
    return toPlainText(para.join(' '))
  }
  return null
}

function convert(file) {
  const raw = readFileSync(file, 'utf8')
  const lines = raw.split('\n')

  const isRootIndex = relative(ROOT, file) === 'README.md'

  let title = relative(ROOT, file)
  let body = lines
  if (lines[0]?.startsWith('# ')) {
    title = unescapeTitle(lines[0])
    body = lines.slice(1)
    while (body[0]?.trim() === '') body = body.slice(1)
  }
  if (isRootIndex) title = 'API / Generated Reference'

  const description = isRootIndex
    ? `Every export of ${PKG_TITLE} in one page, generated straight from source with TypeDoc.`
    : (extractDescription(body) ?? `Generated API reference for ${PKG_TITLE} — ${title}.`)

  const frontmatter = ['---', `title: ${yamlString(title)}`, `description: ${yamlString(description)}`, '---', '']

  const bodyText = body
    .join('\n')
    // Drop the .md extension from relative links; keep anchors and external (http) links untouched.
    .replace(/(\]\((?!https?:\/\/)[^)]*?)\.md(#[^)]*)?\)/g, '$1$2)')

  const dest = file.replace(/\.md$/, '.mdx')
  writeFileSync(dest, `${frontmatter.join('\n')}\n${bodyText}\n`)
  unlinkSync(file)
  return { file, dest, title }
}

const files = walk(ROOT)
const results = files.map(convert)

console.log(`[mdxify-api] converted ${results.length} files to .mdx under ${ROOT}`)
