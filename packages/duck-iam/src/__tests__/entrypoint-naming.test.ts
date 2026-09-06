import { describe, expect, it } from 'vitest'

/**
 * Sixteen subpath entrypoints, each written at a different time, and the
 * package root is not the only namespace a consumer imports into. An audit
 * found the naming had drifted in three separate directions:
 *
 * - **Prefix.** Everything is `Iam` / `iam` / `IAM_` prefixed, except the
 *   verb-first factories - `createIam*`, `withIam*`, `getIam*`.
 * - **Word order.** `createIamRedisInvalidator` and `iamCreateMetricsAggregator`
 *   are the same kind of function under two orderings. `createIam*` wins on
 *   count, 10 to 1.
 * - **Same job, different verb.** The admin mount is `iamAdminRouter` (express),
 *   `iamBindAdminRouter` (hono), `createIamAdminHandlers` (next) and
 *   `createIamAdminOperations` (nest) - four names for one concept, because
 *   each integration mounts it differently.
 *
 * The package is on 5.x, so these are not free to rename. This file does what
 * `public-surface-naming.test.ts` does for the root: it pins the surface so the
 * drift cannot grow, and lists the known outliers explicitly. The list may
 * shrink at a major; nothing may be added to it.
 */

const ENTRYPOINTS = {
  'adapters/drizzle': () => import('../adapters/drizzle'),
  'adapters/file': () => import('../adapters/file'),
  'adapters/http': () => import('../adapters/http'),
  'adapters/memory': () => import('../adapters/memory'),
  'adapters/prisma': () => import('../adapters/prisma'),
  'adapters/redis': () => import('../adapters/redis'),
  'client/react': () => import('../client/react'),
  'client/vanilla': () => import('../client/vanilla'),
  'client/vue': () => import('../client/vue'),
  'invalidators/redis': () => import('../invalidators/redis'),
  'observability/metrics': () => import('../observability/metrics'),
  'server/express': () => import('../server/express'),
  'server/generic': () => import('../server/generic'),
  'server/hono': () => import('../server/hono'),
  'server/nest': () => import('../server/nest'),
  'server/next': () => import('../server/next'),
} as const

/** `Iam`/`iam`/`IAM_`, or a verb-first factory that still carries `Iam`. */
const NAME_SHAPE = /^(Iam|iam|IAM_)|^(create|with|get|generate|check)Iam[A-Z]/

/**
 * Names that break the *word order* rule - `iamCreate…` where the rest of the
 * package says `createIam…` - and the one adapter carrying a third name for its
 * own constructor. Both are 5.x public API.
 */
const NAMING_OUTLIERS = ['createIamDrizzleAdapter', 'iamCreateMetricsAggregator']

type EntrypointName = keyof typeof ENTRYPOINTS

/** `it.each` and `Object.keys` both widen to `string`; narrow back by lookup. */
function isEntrypoint(name: string): name is EntrypointName {
  return Object.hasOwn(ENTRYPOINTS, name)
}

async function exportsOf(name: string): Promise<string[]> {
  if (!isEntrypoint(name)) throw new Error(`unknown entrypoint: ${name}`)
  return Object.keys(await ENTRYPOINTS[name]()).sort()
}

describe('every subpath entrypoint is Iam-namespaced', () => {
  it.each(Object.keys(ENTRYPOINTS))('%s exports only prefixed names', async (name) => {
    const keys = await exportsOf(name)
    // Control: an entrypoint that exported nothing would pass the filter below.
    expect(keys.length).toBeGreaterThan(0)
    expect(keys.filter((k) => !NAME_SHAPE.test(k))).toEqual([])
  })
})

describe('the six adapters are named alike', () => {
  const ADAPTERS = ['memory', 'file', 'prisma', 'drizzle', 'redis', 'http'] as const

  it.each(ADAPTERS)('%s ships a class and a matching lowercase factory', async (kind) => {
    const cased = kind.charAt(0).toUpperCase() + kind.slice(1)
    const keys = await exportsOf(`adapters/${kind}`)
    expect(keys).toContain(`Iam${cased}Adapter`)
    expect(keys).toContain(`iam${cased}Adapter`)
  })

  it('adds nothing beyond that pair except the listed outlier', async () => {
    const extra: string[] = []
    for (const kind of ADAPTERS) {
      const cased = kind.charAt(0).toUpperCase() + kind.slice(1)
      const pair = [`Iam${cased}Adapter`, `iam${cased}Adapter`]
      extra.push(...(await exportsOf(`adapters/${kind}`)).filter((k) => !pair.includes(k)))
    }
    expect(extra).toEqual(['createIamDrizzleAdapter'])
  })
})

describe('factory word order', () => {
  it('is createIam… everywhere but the listed outliers', async () => {
    const wrongOrder: string[] = []
    for (const name of Object.keys(ENTRYPOINTS)) {
      wrongOrder.push(...(await exportsOf(name)).filter((k) => /^iamCreate[A-Z]/.test(k)))
    }
    expect(wrongOrder.filter((k) => !NAMING_OUTLIERS.includes(k))).toEqual([])
  })

  // Positive control: the outlier list is real exports, not stale names that
  // would let the assertion above pass while hiding a rename.
  it('still exports every listed outlier', async () => {
    const all = new Set<string>()
    for (const name of Object.keys(ENTRYPOINTS)) for (const k of await exportsOf(name)) all.add(k)
    expect(NAMING_OUTLIERS.filter((k) => !all.has(k))).toEqual([])
  })
})
