import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import React from 'react'
import { renderToString } from 'react-dom/server'
import { beforeAll, describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine/engine'
import type { Explain } from '../../core/explain'
import { IamDevtools } from '../iam-devtools-panel'
import { iamCreateFlowRecorder } from '../lib/flow'
import { ensureStylesInjected } from '../lib/styles'
import { IamDecisionInspector } from '../panels/decision'
import { IamFlowPanel } from '../panels/flow'
import { IamMetricsPanel } from '../panels/metrics'
import { IamPoliciesPanel } from '../panels/policies'
import { IamRolesPanel } from '../panels/roles'
import { IamSubjectsPanel } from '../panels/subjects'
import { IamTraceTree } from '../panels/trace-tree'

/**
 * `@gentleduck/iam` publishes `./dt`, and `@gentleduck/registry-ui` and
 * `@gentleduck/libs` are *optional* peer dependencies. Six devtools modules
 * imported them unconditionally, so `import '@gentleduck/iam/dt'` threw
 * `ERR_MODULE_NOT_FOUND` for any consumer who installed the package and not
 * those two - and the ones that resolved still rendered unstyled, because the
 * Tailwind utility classes on them only name real CSS if the consumer's
 * Tailwind is configured to scan this package's `dist`, and the `iam-dt-*`
 * rules read `var(--card)` and `var(--border)` with no fallback.
 *
 * None of that is visible from inside this monorepo, where both peers are
 * installed and Tailwind does scan the source - which is why it survived. The
 * checks here are the ones that fail from *here* when the coupling comes back:
 * a source sweep for the peer imports, a sweep for the host tokens, and a
 * cross-check that every `iam-dt-*` class the components emit has a rule in
 * the stylesheet that ships with them.
 */
const dtDir = dirname(dirname(fileURLToPath(import.meta.url)))

/**
 * `src/dt/v2` is the *other* devtools, and it is excluded from every sweep in
 * this file on purpose.
 *
 * v1 and v2 have deliberately opposite dependency contracts: v1 owns its
 * stylesheet and imports no optional peer, v2 is built on duck-ui and imports
 * three of them. Both ship, under separate subpath exports, so a consumer
 * picks the trade they want (`src/dt/v2/index.ts` states both). Sweeping v2
 * with v1's rules would fail every check here for doing exactly what it is
 * for - so the exclusion is real, and
 * `v2/__tests__/v2-contract.test.tsx` is what stops it from becoming a hole:
 * it asserts from the other side that v2 still exists, still imports duck-ui,
 * and is still outside this sweep.
 */
const V2_DIR = 'v2'

/** Every `.ts`/`.tsx` under `src/dt`, tests and `v2/` excluded, as `[relative path, source]`. */
function dtSources(): [string, string][] {
  const out: [string, string][] = []
  const walk = (dir: string, prefix: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === '__tests__') continue
      if (entry.isDirectory() && prefix === '' && entry.name === V2_DIR) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) walk(full, `${prefix}${entry.name}/`)
      else if (/\.tsx?$/.test(entry.name)) out.push([`${prefix}${entry.name}`, readFileSync(full, 'utf8')])
    }
  }
  walk(dtDir, '')
  return out
}

/**
 * The class tokens the components actually emit.
 *
 * Read out of quoted string literals rather than by matching `iam-dt-` in the
 * raw text, so prose in a docblock and the `data-iam-dt-theme` attribute name
 * are not mistaken for classes.
 */
function emittedClasses(sources: [string, string][]): Set<string> {
  const classes = new Set<string>()
  for (const [file, src] of sources) {
    if (file === 'lib/styles.ts') continue // the stylesheet itself, not a consumer of it
    for (const literal of src.match(/'[^'\n]*'|"[^"\n]*"/g) ?? []) {
      for (const token of literal.slice(1, -1).split(/\s+/)) {
        // Underscores included: most of these are BEM, and a pattern that
        // stopped at the hyphen silently dropped every `__element` class -
        // three quarters of the sheet - from the cross-check below.
        if (/^iam-dt[a-z0-9_-]*$/.test(token)) classes.add(token)
      }
    }
  }
  return classes
}

describe('the devtools do not need the optional peer dependencies', () => {
  it('no module under src/dt imports registry-ui or libs', () => {
    const offenders = dtSources()
      .filter(([, src]) => /^\s*import[^\n]*'@gentleduck\/(registry-ui|libs)/m.test(src))
      .map(([file]) => file)
    expect(offenders, 'these modules import an optional peer, so `@gentleduck/iam/dt` fails without it').toEqual([])
  })

  it('sweeps a real set of modules', () => {
    // Anti-vacuity: a sweep that walked an empty tree would pass the check above.
    expect(dtSources().length, 'the sweep found no devtools modules at all').toBeGreaterThanOrEqual(18)
  })

  it('excludes v2 and nothing else', () => {
    // The exclusion is one directory at the top level. A sweep that had
    // quietly grown to skip `panels/` too would still satisfy every check in
    // this file, so name what is missing rather than only what is present.
    expect(dtSources().filter(([file]) => file.startsWith(`${V2_DIR}/`))).toEqual([])
    expect(
      readdirSync(join(dtDir, V2_DIR)).length,
      'src/dt/v2 is empty, so the exclusion hides nothing',
    ).toBeGreaterThan(0)
  })
})

describe('the devtools stylesheet is self-contained', () => {
  // The injected sheet, read back out of the document the way a browser sees it.
  const css = (() => {
    const doc = {
      createElement: () => ({ id: '', textContent: '' }) as unknown as HTMLStyleElement,
      getElementById: () => null,
      head: { appendChild: (_: unknown) => {} },
    }
    let captured = ''
    const stub = {
      ...doc,
      head: {
        appendChild: (el: { textContent: string }) => {
          captured = el.textContent
        },
      },
    }
    const prior = (globalThis as { document?: unknown }).document
    ;(globalThis as { document?: unknown }).document = stub
    try {
      ensureStylesInjected()
    } finally {
      if (prior === undefined) delete (globalThis as { document?: unknown }).document
      else (globalThis as { document?: unknown }).document = prior
    }
    return captured
  })()

  it('reads no CSS variable it does not define itself', () => {
    const foreign = [...new Set(css.match(/var\(\s*--[a-z0-9-]+/g) ?? [])]
      .map((m) => m.replace(/var\(\s*/, ''))
      .filter((name) => !name.startsWith('--iam-dt-'))
    expect(foreign, 'these tokens come from the host theme, which a consumer need not have').toEqual([])
  })

  it('declares its tokens only on the outermost root', () => {
    // Every panel carries `.iam-dt` because each is exported individually, so
    // a nested block would re-derive the theme from `prefers-color-scheme` and
    // overrule the `theme` the root was given.
    const tokenBlocks = css.match(/^\s*\.iam-dt[^{\n]*\{\s*$\n\s*--iam-dt-bg:/gm) ?? []
    expect(tokenBlocks.length, 'expected the dark default, the media light and the attribute light blocks').toBe(3)
    for (const block of tokenBlocks) {
      expect(block, `token block "${block.trim()}" is not root-scoped`).toContain(':not(.iam-dt *)')
    }
  })

  it('has a rule for every class the components emit', () => {
    const missing = [...emittedClasses(dtSources())]
      .filter((cls) => !new RegExp(`\\.${cls.replace(/-/g, '\\-')}(?![a-zA-Z0-9_-])`).test(css))
      .sort()
    expect(missing, 'these classes are rendered but styled by nothing in the injected sheet').toEqual([])
  })

  it('cross-checks a real set of classes', () => {
    // Anti-vacuity again: an empty set satisfies "every class has a rule".
    expect(emittedClasses(dtSources()).size, 'the class sweep matched almost nothing').toBeGreaterThanOrEqual(80)
  })
})

/**
 * A real engine in `development` mode over a real adapter, so the guard lets
 * the panels through on their own signal and the rows they render are the ones
 * the engine actually produces.
 */
const engine = new IamEngine<'read', 'post', 'reader', string, 'development'>({
  adapter: new IamMemoryAdapter<'read', 'post', 'reader', string>({
    assignments: { u1: ['reader'] },
    policies: [
      {
        algorithm: 'deny-overrides',
        id: 'p1',
        name: 'Read posts',
        rules: [
          { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] },
        ],
      },
    ],
    roles: [{ id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'post' }] }],
  }),
  cacheTTL: 0,
  mode: 'development',
})

/** A trace produced by that engine rather than written here, so `IamTraceTree` gets the shape it really receives. */
let trace: Explain.IResult

beforeAll(async () => {
  trace = await engine.explain('u1', 'read', { attributes: {}, type: 'post' })
})

/**
 * Every panel that can be mounted on its own, with the props it needs.
 *
 * `IamFlowPanel` takes a recorder rather than the engine, and `IamTraceTree`
 * takes an already-computed trace, so neither is engine-guarded - but both are
 * exported from `./dt` and both must still bring their own styling.
 */
function standalonePanels(): readonly (readonly [string, () => React.ReactElement])[] {
  return [
    ['IamPoliciesPanel', () => <IamPoliciesPanel engine={engine} />],
    ['IamRolesPanel', () => <IamRolesPanel engine={engine} />],
    ['IamSubjectsPanel', () => <IamSubjectsPanel engine={engine} />],
    ['IamDecisionInspector', () => <IamDecisionInspector engine={engine} />],
    ['IamMetricsPanel', () => <IamMetricsPanel engine={engine} />],
    ['IamFlowPanel', () => <IamFlowPanel flow={iamCreateFlowRecorder()} />],
    ['IamTraceTree', () => <IamTraceTree result={trace} />],
  ] as const
}

describe('a panel mounted on its own is its own themed root', () => {
  it.each(standalonePanels())('%s renders an .iam-dt root', (_name, element) => {
    const html = renderToString(element())
    // The tokens live on `.iam-dt`. A panel whose outermost element lacks the
    // class renders every colour as an unresolved `var()` - transparent text
    // on a transparent ground.
    expect(html.slice(0, 200)).toMatch(/^<[a-z]+ class="iam-dt(\s|")/)
  })

  it('every panel module injects the stylesheet', () => {
    // `ensureStylesInjected` used to be called by the two shells only, so a
    // directly imported panel rendered with no `<style>` in the document.
    const offenders = dtSources()
      .filter(
        ([file]) => file.startsWith('panels/') || file === 'iam-devtools.tsx' || file === 'iam-devtools-panel.tsx',
      )
      .filter(([, src]) => !src.includes('useIamDevtoolsStyles()'))
      .map(([file]) => file)
    expect(offenders, 'these render without ensuring the stylesheet is present').toEqual([])
  })
})

describe('the theme prop reaches the DOM', () => {
  it.each([
    ['light', 'data-iam-dt-theme="light"'],
    ['dark', 'data-iam-dt-theme="dark"'],
  ] as const)('theme=%s stamps the root', (theme, attr) => {
    const html = renderToString(<IamDevtools engine={engine} initialIsOpen theme={theme} />)
    expect(html).toContain(attr)
  })

  it('the default leaves the choice to prefers-color-scheme', () => {
    // Absent, not `auto`: the stylesheet keys its light palette off the media
    // query *unless* an explicit value is present, so a value the CSS ignores
    // would pin dark on a light desktop.
    const html = renderToString(<IamDevtools engine={engine} initialIsOpen />)
    expect(html).not.toContain('data-iam-dt-theme')
    expect(html, 'the panel did not render at all, so the check above is vacuous').toContain('iam-dt-dock')
  })
})
