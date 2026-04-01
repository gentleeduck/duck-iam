import { DashboardTableOfContents, DocsCopyPage, DocsPagerBottom, DocsPagerTop } from '@gentleduck/docs/client'
import { absoluteUrl } from '@gentleduck/docs/lib'
import { cn } from '@gentleduck/libs/cn'
import { badgeVariants } from '@gentleduck/registry-ui/badge'
import { Button } from '@gentleduck/registry-ui/button'
import { Separator } from '@gentleduck/registry-ui/separator'
import { ArrowDownIcon, ArrowUpIcon, ExternalLinkIcon, SquareArrowOutUpRight } from 'lucide-react'
import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { BundleSizeChart, InternalPerfChart, ModuleSizesChart, PerformanceBarChart } from '~/components/benchmarks'
import { DocsPathBreadcrumb } from '~/components/docs-path-breadcrumb'
import { SLUG_METADATA } from '~/config/metadata'
import { docs } from '../../../../.velite'

export const dynamic = 'force-static'

function getBenchmarksDoc() {
  return docs.find((d) => d.permalink === 'benchmarks' || d.slug === 'docs/benchmarks') ?? null
}

export async function generateMetadata(): Promise<Metadata> {
  const doc = getBenchmarksDoc()
  if (!doc) return {}
  return SLUG_METADATA(doc)
}

export default function BenchmarksPage() {
  const doc = getBenchmarksDoc()
  if (!doc) notFound()

  return (
    <main className="relative py-6 lg:gap-10 lg:py-8 xl:grid xl:grid-cols-[1fr_300px]">
      <div className="relative mx-auto w-full min-w-0 max-w-2xl">
        {/* Header */}
        <div className="mb-4 flex h-8 items-center justify-between gap-2">
          <DocsPathBreadcrumb segments={['benchmarks']} />
          <div className="flex-1" />
          <div className="flex items-center gap-2">
            <DocsCopyPage page={doc.content} url={absoluteUrl(doc.slug)} />
            <DocsPagerTop doc={doc} />
          </div>
        </div>

        <div className="space-y-2">
          <h1 className={cn('scroll-m-20 font-bold text-3xl capitalize tracking-tight')}>Benchmarks</h1>
          {doc.description && <p className="text-base text-muted-foreground">{doc.description}</p>}
        </div>

        {doc.links ? (
          <div className="flex items-center space-x-2 pt-4">
            {doc.links?.doc && (
              <Link
                className={cn(badgeVariants({ variant: 'secondary' }), 'gap-1')}
                href={doc.links.doc}
                rel="noreferrer"
                target="_blank">
                Docs
                <ExternalLinkIcon aria-hidden="true" className="h-3 w-3" />
                <span className="sr-only"> (opens in a new tab)</span>
              </Link>
            )}
            {doc.links?.api && (
              <Link
                className={cn(badgeVariants({ variant: 'secondary' }), 'gap-1')}
                href={doc.links.api}
                rel="noreferrer"
                target="_blank">
                API Reference
                <ExternalLinkIcon aria-hidden="true" className="h-3 w-3" />
                <span className="sr-only"> (opens in a new tab)</span>
              </Link>
            )}
          </div>
        ) : null}

        {/* Content */}
        <div className="prose prose-neutral dark:prose-invert max-w-none pt-8 pb-12">
          <p>
            Benchmarked against <strong>7 libraries</strong>: @casl/ability, casbin, accesscontrol, role-acl,
            @rbac/rbac, and easy-rbac. All numbers from <code>vitest bench</code> with identical authorization
            scenarios. Sizes verified via bundlephobia on 2026-03-30.
          </p>
          <p>
            Run <code>bun run bench</code> in <code>packages/duck-iam</code> to reproduce every number on this page.
          </p>

          <Separator className="my-8" />

          {/* The honest verdict */}
          <h2 id="the-honest-verdict" className="scroll-m-20">
            The honest verdict
          </h2>
          <p>
            <strong>CASL is faster than us.</strong> On simple RBAC checks, CASL is ~2x faster in production mode
            because it pre-compiles rules into a hash-map index at build time. We cannot fully match that because
            duck-iam supports dynamic policies that change at runtime.
          </p>
          <p>
            <strong>We are faster than everyone else.</strong> In production mode, duck-iam is 3-50x faster than casbin,
            role-acl, accesscontrol, and @rbac/rbac.
          </p>
          <p>
            <strong>We ship more features than anyone.</strong> Scoped roles, explain/debug traces, lifecycle hooks,
            batch permissions, 18 condition operators, 5 server middlewares, 3 client libraries — no competitor bundles
            all of these together.
          </p>
          <p>
            <strong>We are larger than CASL.</strong> ~21 KB vs ~6 KB. That is because we include a full policy engine,
            RBAC-to-ABAC converter, explain tracer, builder, config validator, and LRU cache. CASL does not ship any of
            that.
          </p>

          <Separator className="my-8" />

          {/* Library Overview */}
          <h2 id="library-overview" className="scroll-m-20">
            Library Overview
          </h2>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th />
                  <th>@gentleduck/iam</th>
                  <th>@casl/ability</th>
                  <th>casbin</th>
                  <th>accesscontrol</th>
                  <th>role-acl</th>
                  <th>@rbac/rbac</th>
                  <th>easy-rbac</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <strong>Model</strong>
                  </td>
                  <td>Policy engine</td>
                  <td>Ability-based</td>
                  <td>PERM DSL</td>
                  <td>Fluent grants</td>
                  <td>Role + conditions</td>
                  <td>Hierarchical</td>
                  <td>Hierarchical</td>
                </tr>
                <tr>
                  <td>
                    <strong>ABAC</strong>
                  </td>
                  <td>Yes (18 ops)</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>RBAC</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                </tr>
                <tr>
                  <td>
                    <strong>Runtime deps</strong>
                  </td>
                  <td>0</td>
                  <td>0</td>
                  <td>5</td>
                  <td>1</td>
                  <td>3</td>
                  <td>0</td>
                  <td>0</td>
                </tr>
                <tr>
                  <td>
                    <strong>TypeScript</strong>
                  </td>
                  <td>Full generics</td>
                  <td>Full</td>
                  <td>String-based</td>
                  <td>Partial</td>
                  <td>Partial</td>
                  <td>Yes</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Maintained</strong>
                  </td>
                  <td>Active</td>
                  <td>Active</td>
                  <td>Active</td>
                  <td>No (2020)</td>
                  <td>Active</td>
                  <td>Active</td>
                  <td>No (2021)</td>
                </tr>
              </tbody>
            </table>
          </div>

          <Separator className="my-8" />

          {/* Runtime Performance */}
          <h2 id="runtime-performance" className="scroll-m-20">
            Runtime Performance
          </h2>
          <p>
            All numbers are <strong>ops/sec</strong> (higher = faster). Each library solves the <strong>same</strong>{' '}
            authorization problem. CASL condition checks use <code>subject()</code> to actually evaluate conditions (not
            bare strings that skip them). duck-iam has two modes: <code>[DEV]</code> returns rich Decision objects with
            timing and reasons, <code>[PROD]</code> returns plain booleans with zero overhead.
          </p>

          <h3 id="simple-rbac" className="scroll-m-20">
            Simple RBAC: &quot;can viewer read post?&quot;
          </h3>
          <PerformanceBarChart />
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Library</th>
                  <th>ops/sec</th>
                  <th>vs CASL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td>
                    <strong>@casl/ability</strong>
                  </td>
                  <td>15,420,000</td>
                  <td>—</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>
                    @gentleduck/iam <code>evaluatePolicyFast()</code> [PROD]
                  </td>
                  <td>8,060,000</td>
                  <td>1.9x slower</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>
                    @gentleduck/iam <code>evaluateFast()</code> [PROD]
                  </td>
                  <td>7,560,000</td>
                  <td>2x slower</td>
                </tr>
                <tr>
                  <td>4</td>
                  <td>easy-rbac</td>
                  <td>4,050,000</td>
                  <td>3.8x slower</td>
                </tr>
                <tr>
                  <td>5</td>
                  <td>@rbac/rbac</td>
                  <td>2,490,000</td>
                  <td>6.2x slower</td>
                </tr>
                <tr>
                  <td>6</td>
                  <td>
                    @gentleduck/iam <code>evaluatePolicy()</code> [DEV]
                  </td>
                  <td>1,180,000</td>
                  <td>13x slower</td>
                </tr>
                <tr>
                  <td>7</td>
                  <td>
                    @gentleduck/iam <code>evaluate()</code> [DEV]
                  </td>
                  <td>920,000</td>
                  <td>17x slower</td>
                </tr>
                <tr>
                  <td>8</td>
                  <td>accesscontrol</td>
                  <td>600,000</td>
                  <td>26x slower</td>
                </tr>
                <tr>
                  <td>9</td>
                  <td>casbin</td>
                  <td>118,000</td>
                  <td>131x slower</td>
                </tr>
                <tr>
                  <td>10</td>
                  <td>role-acl</td>
                  <td>104,000</td>
                  <td>148x slower</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 id="abac-condition-check" className="scroll-m-20">
            ABAC condition check: &quot;can owner update own draft?&quot;
          </h3>
          <p>
            Only libraries with real ABAC condition support. CASL uses <code>subject()</code> to actually check
            conditions.
          </p>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Library</th>
                  <th>ops/sec</th>
                  <th>vs CASL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td>
                    <strong>@casl/ability</strong> (with <code>subject()</code>)
                  </td>
                  <td>3,400,000</td>
                  <td>—</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>
                    @gentleduck/iam <code>evaluateFast()</code> [PROD]
                  </td>
                  <td>1,028,000</td>
                  <td>3.3x slower</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>
                    @gentleduck/iam <code>evaluate()</code> [DEV]
                  </td>
                  <td>480,000</td>
                  <td>7.1x slower</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p>Others excluded — they do not support attribute-based conditions.</p>

          <h3 id="role-condition" className="scroll-m-20">
            Role + condition: &quot;can admin delete post?&quot;
          </h3>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Library</th>
                  <th>ops/sec</th>
                  <th>vs CASL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td>
                    <strong>@casl/ability</strong> (with <code>subject()</code>)
                  </td>
                  <td>5,040,000</td>
                  <td>—</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>easy-rbac</td>
                  <td>3,660,000</td>
                  <td>1.4x slower</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>@rbac/rbac</td>
                  <td>2,280,000</td>
                  <td>2.2x slower</td>
                </tr>
                <tr>
                  <td>4</td>
                  <td>@gentleduck/iam [DEV]</td>
                  <td>670,000</td>
                  <td>7.5x slower</td>
                </tr>
                <tr>
                  <td>5</td>
                  <td>accesscontrol</td>
                  <td>330,000</td>
                  <td>15x slower</td>
                </tr>
                <tr>
                  <td>6</td>
                  <td>casbin</td>
                  <td>45,000</td>
                  <td>112x slower</td>
                </tr>
                <tr>
                  <td>7</td>
                  <td>role-acl</td>
                  <td>44,000</td>
                  <td>115x slower</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 id="deny-path" className="scroll-m-20">
            Deny path: &quot;viewer cannot delete&quot;
          </h3>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Library</th>
                  <th>ops/sec</th>
                  <th>vs fastest</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td>
                    <strong>easy-rbac</strong>
                  </td>
                  <td>2,970,000</td>
                  <td>—</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>@casl/ability</td>
                  <td>1,360,000</td>
                  <td>2.2x slower</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>@gentleduck/iam [DEV]</td>
                  <td>690,000</td>
                  <td>4.3x slower</td>
                </tr>
                <tr>
                  <td>4</td>
                  <td>role-acl</td>
                  <td>120,000</td>
                  <td>25x slower</td>
                </tr>
                <tr>
                  <td>5</td>
                  <td>@rbac/rbac</td>
                  <td>61,000</td>
                  <td>49x slower</td>
                </tr>
                <tr>
                  <td>6</td>
                  <td>casbin</td>
                  <td>45,000</td>
                  <td>66x slower</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 id="batch-20-permission-checks" className="scroll-m-20">
            Batch: 20 permission checks
          </h3>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Library</th>
                  <th>ops/sec</th>
                  <th>vs CASL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td>
                    <strong>@casl/ability</strong>
                  </td>
                  <td>3,330,000</td>
                  <td>—</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>easy-rbac</td>
                  <td>469,000</td>
                  <td>7.1x slower</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>
                    @gentleduck/iam <code>evaluateFast()</code> [PROD]
                  </td>
                  <td>424,000</td>
                  <td>7.9x slower</td>
                </tr>
                <tr>
                  <td>4</td>
                  <td>
                    @gentleduck/iam <code>evaluate()</code> [DEV]
                  </td>
                  <td>121,000</td>
                  <td>27x slower</td>
                </tr>
                <tr>
                  <td>5</td>
                  <td>accesscontrol</td>
                  <td>60,000</td>
                  <td>56x slower</td>
                </tr>
                <tr>
                  <td>6</td>
                  <td>role-acl</td>
                  <td>18,500</td>
                  <td>180x slower</td>
                </tr>
                <tr>
                  <td>7</td>
                  <td>@rbac/rbac</td>
                  <td>12,900</td>
                  <td>258x slower</td>
                </tr>
                <tr>
                  <td>8</td>
                  <td>casbin</td>
                  <td>8,500</td>
                  <td>392x slower</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 id="cold-start" className="scroll-m-20">
            Cold start: build everything + first check
          </h3>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Library</th>
                  <th>ops/sec</th>
                  <th>vs CASL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>1</td>
                  <td>
                    <strong>@casl/ability</strong>
                  </td>
                  <td>2,950,000</td>
                  <td>—</td>
                </tr>
                <tr>
                  <td>2</td>
                  <td>easy-rbac</td>
                  <td>2,730,000</td>
                  <td>1.1x slower</td>
                </tr>
                <tr>
                  <td>3</td>
                  <td>accesscontrol</td>
                  <td>735,000</td>
                  <td>4x slower</td>
                </tr>
                <tr>
                  <td>4</td>
                  <td>@gentleduck/iam</td>
                  <td>285,000</td>
                  <td>10x slower</td>
                </tr>
                <tr>
                  <td>5</td>
                  <td>role-acl</td>
                  <td>262,000</td>
                  <td>11x slower</td>
                </tr>
                <tr>
                  <td>6</td>
                  <td>@rbac/rbac</td>
                  <td>164,000</td>
                  <td>18x slower</td>
                </tr>
                <tr>
                  <td>7</td>
                  <td>casbin</td>
                  <td>54,000</td>
                  <td>55x slower</td>
                </tr>
              </tbody>
            </table>
          </div>

          <Separator className="my-8" />

          {/* Why CASL is faster */}
          <h2 id="why-casl-is-faster" className="scroll-m-20">
            Why CASL is faster — and why it matters less than you think
          </h2>

          <h3 id="the-architectural-difference" className="scroll-m-20">
            The architectural difference
          </h3>
          <p>CASL and duck-iam solve authorization differently at the engine level:</p>
          <p>
            <strong>CASL: pre-compiled lookup table.</strong> When you call <code>build()</code>, CASL iterates all
            rules once and builds an internal index keyed by <code>[action, subjectType]</code>. Every subsequent{' '}
            <code>can()</code> call does a single hash-map lookup — O(1), ~0.012 us. The rules are frozen after{' '}
            <code>build()</code> and cannot change at runtime.
          </p>
          <p>
            <strong>duck-iam: dynamic policy engine.</strong> Policies can be loaded from databases, updated at runtime
            via adapters, and invalidated via the LRU cache. Each evaluation does: WeakMap index lookup → Map.get by{' '}
            <code>action:resource</code> → condition evaluation → combining algorithm. Even with our rule index
            optimization, each check costs ~0.06 us — about 5x more than a single hash lookup.
          </p>

          <h3 id="where-the-2x-gap-comes-from" className="scroll-m-20">
            Where the ~2x gap comes from (profiled)
          </h3>
          <p>Profiled operations in the production fast path:</p>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Operation</th>
                  <th>Cost</th>
                  <th>What it does</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>WeakMap index lookup</td>
                  <td>~0.004 us</td>
                  <td>Retrieve cached rule index for the policy</td>
                </tr>
                <tr>
                  <td>String key concat</td>
                  <td>~0.001 us</td>
                  <td>
                    Build <code>{'"read\\0post"'}</code> lookup key
                  </td>
                </tr>
                <tr>
                  <td>Map.get</td>
                  <td>~0.014 us</td>
                  <td>Find rules matching this action+resource</td>
                </tr>
                <tr>
                  <td>for loop (1 rule)</td>
                  <td>~0.003 us</td>
                  <td>Iterate matched rules</td>
                </tr>
                <tr>
                  <td>Condition check</td>
                  <td>~0.003 us</td>
                  <td>Skip (empty conditions) or evaluate</td>
                </tr>
                <tr>
                  <td>policyApplies</td>
                  <td>~0.003 us</td>
                  <td>Check policy targets</td>
                </tr>
                <tr>
                  <td>Function overhead</td>
                  <td>~0.030 us</td>
                  <td>Call stack, argument passing</td>
                </tr>
                <tr>
                  <td>
                    <strong>Total</strong>
                  </td>
                  <td>
                    <strong>~0.058 us</strong>
                  </td>
                  <td />
                </tr>
                <tr>
                  <td>
                    <strong>CASL total</strong>
                  </td>
                  <td>
                    <strong>~0.012 us</strong>
                  </td>
                  <td>Single hash lookup + return</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p>
            The gap is not one big bottleneck — it is the sum of many small costs that a policy engine fundamentally
            requires. CASL avoids all of them by freezing rules at build time.
          </p>

          <h3 id="what-we-optimized" className="scroll-m-20">
            What we optimized (and what we cannot)
          </h3>
          <p>Every optimization that preserves the dynamic policy model is already applied:</p>
          <ol>
            <li>
              <strong>Rule indexing</strong> — pre-built <code>{'Map<action:resource, Rule[]>'}</code> per policy,
              cached via WeakMap. Eliminates the linear scan over all rules.
            </li>
            <li>
              <strong>Unconditional rule flag</strong> — rules with empty conditions skip{' '}
              <code>evalConditionGroup()</code> entirely.
            </li>
            <li>
              <strong>Inlined combiners</strong> — <code>deny-overrides</code> and <code>allow-overrides</code> are
              inlined directly into the evaluation loop, avoiding array allocation and function calls.
            </li>
            <li>
              <strong>Path cache</strong> — condition field paths like <code>subject.attributes.role</code> are split
              once and cached forever.
            </li>
            <li>
              <strong>Production mode</strong> — no <code>performance.now()</code>, no <code>Date.now()</code>, no
              Decision object allocation, no reason strings.
            </li>
          </ol>
          <p>
            To close the remaining ~2x gap, we would need to abandon dynamic policies and pre-compile everything at init
            time like CASL does. That would break adapters, runtime policy updates, and the LRU cache — the features
            that make duck-iam a policy engine instead of a lookup table.
          </p>

          <h3 id="why-it-doesnt-matter" className="scroll-m-20">
            Why it does not matter in practice
          </h3>
          <p>Authorization is never your bottleneck. Here is a typical API request:</p>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Network round trip</td>
                  <td>5,000–50,000 us</td>
                </tr>
                <tr>
                  <td>Database query</td>
                  <td>500–5,000 us</td>
                </tr>
                <tr>
                  <td>JSON serialization</td>
                  <td>50–500 us</td>
                </tr>
                <tr>
                  <td>
                    <strong>duck-iam check (prod)</strong>
                  </td>
                  <td>
                    <strong>0.06 us</strong>
                  </td>
                </tr>
                <tr>
                  <td>
                    <strong>CASL check</strong>
                  </td>
                  <td>
                    <strong>0.012 us</strong>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p>
            The gap is 48 nanoseconds. At 100 checks per request that is 4.8 us — 0.0001% of a typical 50 ms request.
          </p>

          <Separator className="my-8" />

          {/* Dev vs Prod Mode */}
          <h2 id="dev-vs-prod-mode" className="scroll-m-20">
            Dev vs Prod Mode
          </h2>
          <p>
            duck-iam has two execution modes that change both <strong>runtime behavior</strong> and{' '}
            <strong>return types</strong>:
          </p>
          <pre className="overflow-x-auto">
            <code>{`// Development (default) — rich Decision with timing, reasons, rule refs
const engine = new Engine({ adapter, mode: 'development' })
const decision = await engine.check('user-1', 'read', post)
// decision: Decision { allowed: true, effect: 'allow', reason: '...', duration: 0.5, timestamp: ... }
// engine.explain() is available
// Hooks (afterEvaluate, onDeny, onError) fire on every check

// Production — plain boolean, maximum throughput
const prodEngine = new Engine({ adapter, mode: 'production' })
const allowed = await prodEngine.check('user-1', 'read', post)
// allowed: true (boolean)
// No performance.now(), no Date.now(), no object allocation, no reason strings
// engine.explain() throws — not available in production
// Hooks (afterEvaluate, onDeny, onError) are skipped for maximum speed`}</code>
          </pre>
          <p>
            <code>engine.can()</code> always returns <code>boolean</code> in both modes (for middleware compatibility).
          </p>

          <h3 id="production-mode-bundle-size" className="scroll-m-20">
            Does production mode reduce bundle size?
          </h3>
          <p>
            <strong>
              The <code>mode</code> flag alone does not reduce bundle size
            </strong>{' '}
            — it is a runtime check. However, <strong>your import pattern does</strong>. The package is tree-shakeable,
            so bundlers eliminate code you do not import:
          </p>
          <pre className="overflow-x-auto">
            <code>{`// Smallest production bundle — import only the fast evaluator
// Tree-shakes away: Engine, explain, builder, config, validate, dev evaluate
import { evaluateFast } from '@gentleduck/iam'
const allowed = evaluateFast(policies, request) // boolean

// Full engine — includes everything (dev + prod paths)
import { Engine } from '@gentleduck/iam'`}</code>
          </pre>
          <p>
            <code>evaluateFast</code> + <code>evaluatePolicyFast</code> give the smallest bundle when you manage
            policies yourself. The Engine, explain system, builder, and config validator are only included if you import
            them.
          </p>
          <p>
            <code>engine.explain()</code> is only available in development mode.
          </p>

          <Separator className="my-8" />

          {/* Internal Performance */}
          <h2 id="internal-performance" className="scroll-m-20">
            Internal Performance
          </h2>
          <p>Pure evaluation timing — average of 2,000 iterations after 200 warmup rounds.</p>
          <InternalPerfChart />
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Operation</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <code>evaluatePolicyFast()</code> — simple rule
                  </td>
                  <td>~0.06 us</td>
                </tr>
                <tr>
                  <td>
                    <code>evaluatePolicyFast()</code> — with conditions
                  </td>
                  <td>~0.10 us</td>
                </tr>
                <tr>
                  <td>
                    <code>evaluatePolicy()</code> [DEV] — simple rule
                  </td>
                  <td>~0.17 us</td>
                </tr>
                <tr>
                  <td>
                    <code>evaluatePolicy()</code> [DEV] — with conditions
                  </td>
                  <td>~0.33 us</td>
                </tr>
                <tr>
                  <td>
                    <code>evaluatePolicy()</code> — target skip
                  </td>
                  <td>~0.24 us</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 id="engine-performance" className="scroll-m-20">
            Engine Performance (with LRU caching)
          </h3>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Operation</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <code>engine.can()</code> — cached
                  </td>
                  <td>~7.5 us</td>
                </tr>
                <tr>
                  <td>
                    <code>engine.check()</code> — cached
                  </td>
                  <td>~7.5 us</td>
                </tr>
                <tr>
                  <td>
                    <code>engine.permissions()</code> — 20 checks
                  </td>
                  <td>~20 us</td>
                </tr>
                <tr>
                  <td>
                    <code>engine.explain()</code> — full trace
                  </td>
                  <td>~10 us</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p>
            Times vary by machine. Run <code>bun run benchmark</code> for your hardware.
          </p>

          <Separator className="my-8" />

          {/* Bundle Size */}
          <h2 id="bundle-size" className="scroll-m-20">
            Bundle Size
          </h2>
          <BundleSizeChart />
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Library</th>
                  <th>Size (gzip)</th>
                  <th>Runtime deps</th>
                  <th>Tree-shakeable</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>easy-rbac</td>
                  <td>~2 KB</td>
                  <td>0</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>@rbac/rbac</td>
                  <td>~4 KB</td>
                  <td>0</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>@casl/ability</strong>
                  </td>
                  <td>~6 KB</td>
                  <td>0</td>
                  <td>Yes</td>
                </tr>
                <tr>
                  <td>accesscontrol</td>
                  <td>~8.2 KB</td>
                  <td>1</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>role-acl</td>
                  <td>~12 KB</td>
                  <td>3</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>@gentleduck/iam</strong> (full)
                  </td>
                  <td>~21 KB</td>
                  <td>0</td>
                  <td>Yes</td>
                </tr>
                <tr>
                  <td>casbin (node-casbin)</td>
                  <td>~30 KB</td>
                  <td>5</td>
                  <td>No</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p>
            <strong>We are not the smallest.</strong> At ~21 KB, duck-iam is 3.5x larger than CASL. That is because the
            full package includes: evaluation engine, RBAC-to-ABAC converter, conditions engine (18 operators),
            explain/debug tracer, type-safe builder, config validator, and LRU cache. CASL ships none of that.
          </p>
          <p>
            <strong>The package is tree-shakeable.</strong> Import only <code>evaluateFast</code> and skip the
            engine/explain/builder for a much smaller bundle. Individual adapters and server middleware add ~0.8-1.7 KB
            each.
          </p>

          <h3 id="module-sizes" className="scroll-m-20">
            Module Sizes
          </h3>
          <ModuleSizesChart />
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Size (gzip)</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Core (full entry)</td>
                  <td>21.9 KB</td>
                </tr>
                <tr>
                  <td>Adapter: Memory</td>
                  <td>1.1 KB</td>
                </tr>
                <tr>
                  <td>Adapter: Prisma</td>
                  <td>1.4 KB</td>
                </tr>
                <tr>
                  <td>Adapter: Drizzle</td>
                  <td>1.7 KB</td>
                </tr>
                <tr>
                  <td>Adapter: HTTP</td>
                  <td>1.2 KB</td>
                </tr>
                <tr>
                  <td>Server: Express</td>
                  <td>1.1 KB</td>
                </tr>
                <tr>
                  <td>Server: Next.js</td>
                  <td>1.0 KB</td>
                </tr>
                <tr>
                  <td>Server: Hono</td>
                  <td>0.9 KB</td>
                </tr>
                <tr>
                  <td>Server: NestJS</td>
                  <td>1.3 KB</td>
                </tr>
                <tr>
                  <td>Server: Generic</td>
                  <td>0.8 KB</td>
                </tr>
                <tr>
                  <td>Client: React</td>
                  <td>1.1 KB</td>
                </tr>
                <tr>
                  <td>Client: Vue</td>
                  <td>1.0 KB</td>
                </tr>
                <tr>
                  <td>Client: Vanilla</td>
                  <td>1.4 KB</td>
                </tr>
              </tbody>
            </table>
          </div>

          <Separator className="my-8" />

          {/* Feature Comparison */}
          <h2 id="feature-comparison" className="scroll-m-20">
            Feature Comparison
          </h2>
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>gentleduck</th>
                  <th>CASL</th>
                  <th>Casbin</th>
                  <th>accesscontrol</th>
                  <th>role-acl</th>
                  <th>@rbac/rbac</th>
                  <th>easy-rbac</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <strong>RBAC</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>Yes</td>
                </tr>
                <tr>
                  <td>
                    <strong>ABAC (conditions)</strong>
                  </td>
                  <td>18 operators</td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Policy engine</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Dev/Prod mode</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Deny-overrides</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Combining algorithms</strong>
                  </td>
                  <td>4</td>
                  <td>1</td>
                  <td>Custom</td>
                  <td>1</td>
                  <td>1</td>
                  <td>1</td>
                  <td>1</td>
                </tr>
                <tr>
                  <td>
                    <strong>Scoped roles</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Explain / debug</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Lifecycle hooks</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>LRU caching</strong>
                  </td>
                  <td>Built-in</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Rule indexing</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>DB adapters</strong>
                  </td>
                  <td>4</td>
                  <td>3</td>
                  <td>20+</td>
                  <td>0</td>
                  <td>0</td>
                  <td>3</td>
                  <td>0</td>
                </tr>
                <tr>
                  <td>
                    <strong>Server middleware</strong>
                  </td>
                  <td>5</td>
                  <td>0</td>
                  <td>2</td>
                  <td>0</td>
                  <td>0</td>
                  <td>3</td>
                  <td>0</td>
                </tr>
                <tr>
                  <td>
                    <strong>React integration</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Vue integration</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Type-safe config</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>No</td>
                </tr>
                <tr>
                  <td>
                    <strong>Zero runtime deps</strong>
                  </td>
                  <td>Yes</td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>Yes</td>
                  <td>Yes</td>
                </tr>
                <tr>
                  <td>
                    <strong>Batch permissions</strong>
                  </td>
                  <td>Yes</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                  <td>No</td>
                </tr>
              </tbody>
            </table>
          </div>

          <Separator className="my-8" />

          {/* Where each library wins */}
          <h2 id="where-each-library-wins" className="scroll-m-20">
            Where each library wins
          </h2>

          <h3 id="gentleduck-iam-wins-on" className="scroll-m-20">
            @gentleduck/iam wins on
          </h3>
          <ul>
            <li>
              <strong>Feature density</strong> — the only library with scoped roles + explain/debug + lifecycle hooks +
              batch permissions + 18 condition operators + dev/prod mode combined
            </li>
            <li>
              <strong>Faster than casbin/role-acl/accesscontrol</strong> — 3-50x faster in production mode
            </li>
            <li>
              <strong>Server integration</strong> — 5 framework middlewares (Express, Next.js, Hono, NestJS, Generic)
            </li>
            <li>
              <strong>Client libraries</strong> — React, Vue, and Vanilla JS with hooks and reactive state
            </li>
            <li>
              <strong>Type safety</strong> — full generic type parameters for actions, resources, roles, and scopes
            </li>
            <li>
              <strong>Explain API</strong> — the only library that tells you exactly why a permission was granted or
              denied
            </li>
            <li>
              <strong>Dev/Prod mode</strong> — rich debug objects in development, fast booleans in production
            </li>
          </ul>

          <h3 id="casl-ability-wins-on" className="scroll-m-20">
            @casl/ability wins on
          </h3>
          <ul>
            <li>
              <strong>Raw speed</strong> — 2x faster than duck-iam in production mode thanks to pre-compiled ability
              index
            </li>
            <li>
              <strong>Bundle size</strong> — ~6 KB, 3.5x smaller
            </li>
            <li>
              <strong>Maturity</strong> — production since 2017
            </li>
            <li>
              <strong>Ecosystem</strong> — ~900K downloads/week, extensive docs and community
            </li>
            <li>
              <strong>Isomorphic</strong> — proven frontend + backend sharing pattern
            </li>
          </ul>

          <h3 id="easy-rbac-wins-on" className="scroll-m-20">
            easy-rbac wins on
          </h3>
          <ul>
            <li>
              <strong>Fastest deny path</strong> — 2x faster than CASL for deny checks
            </li>
            <li>
              <strong>Tiny bundle</strong> — ~2 KB, smallest of all
            </li>
            <li>
              <strong>Zero config</strong> — dead-simple hierarchical RBAC
            </li>
          </ul>

          <h3 id="casbin-wins-on" className="scroll-m-20">
            casbin wins on
          </h3>
          <ul>
            <li>
              <strong>Adapter ecosystem</strong> — 20+ database adapters across 15+ languages
            </li>
            <li>
              <strong>Admin UI</strong> — web-based policy management panel
            </li>
            <li>
              <strong>Academic backing</strong> — formal PERM metamodel
            </li>
          </ul>

          <h3 id="rbac-rbac-wins-on" className="scroll-m-20">
            @rbac/rbac wins on
          </h3>
          <ul>
            <li>
              <strong>Fast simple checks</strong> — 2.5M ops/sec for basic RBAC
            </li>
            <li>
              <strong>Built-in middleware</strong> — Express, NestJS, Fastify
            </li>
            <li>
              <strong>Runtime role updates</strong> — add/modify roles without restart
            </li>
          </ul>

          <Separator className="my-8" />

          {/* Methodology */}
          <h2 id="methodology" className="scroll-m-20">
            Methodology
          </h2>
          <ul>
            <li>
              <strong>@gentleduck/iam</strong>: bundle sizes from <code>dist/</code> via <code>gzip -c | wc -c</code>.
              Performance via <code>vitest bench</code> with N=3 inner loops. Production mode uses{' '}
              <code>evaluateFast()</code> with rule indexing (WeakMap-cached per policy, Map lookup by{' '}
              <code>action:resource</code>).
            </li>
            <li>
              <strong>@casl/ability</strong>: condition benchmarks use <code>subject()</code> for real condition
              evaluation. Bare string checks (<code>can('read', 'Post')</code>) skip conditions and would give
              misleading results — we do not do that.
            </li>
            <li>
              <strong>casbin</strong>: real RBAC model (<code>newModel()</code> + <code>StringAdapter</code>) with role
              inheritance via grouping rules.
            </li>
            <li>
              <strong>accesscontrol, @rbac/rbac, easy-rbac</strong>: excluded from ABAC benchmarks (no condition
              support).
            </li>
            <li>
              Competitor sizes from{' '}
              <a href="https://bundlephobia.com" target="_blank" rel="noreferrer">
                bundlephobia.com
              </a>
              , verified 2026-03-30.
            </li>
            <li>
              All sizes are <strong>minified + gzipped</strong>.
            </li>
            <li>All benchmarks run on the same machine in the same vitest session.</li>
          </ul>
          <p>To reproduce:</p>
          <pre className="overflow-x-auto">
            <code>{`cd packages/duck-iam
bun run bench       # vitest bench — competitive comparison
bun run benchmark   # JSON data output + console summary`}</code>
          </pre>
        </div>

        <DocsPagerBottom doc={doc} />
        <div aria-hidden="true" id="bottom" />
      </div>

      {doc.toc && (
        <div className="hidden text-sm xl:block">
          <div className="sticky top-16 -mt-10 flex h-[calc(100vh-3.5rem)] flex-col py-12">
            <DashboardTableOfContents toc={doc.toc} />
            <Separator className="my-4 shrink-0" />
            <div className="flex shrink-0 flex-col gap-1">
              <Button asChild className="justify-start" size="sm" variant="link">
                <a
                  href="https://github.com/gentleeduck/duck-iam/blob/master/apps/duck-iam-docs/content/docs/benchmarks.mdx"
                  rel="noreferrer"
                  target="_blank">
                  <SquareArrowOutUpRight aria-hidden="true" className="size-3.5" />
                  Edit this page on GitHub
                </a>
              </Button>
              <Button asChild className="justify-start" size="sm" variant="link">
                {/** biome-ignore lint/a11y/useValidAnchor: This is a link to the top of the page */}
                <a href="#">
                  <ArrowUpIcon aria-hidden="true" className="size-3.5" />
                  Scroll to top
                </a>
              </Button>
              <Button asChild className="justify-start" size="sm" variant="link">
                <a href="#bottom">
                  <ArrowDownIcon aria-hidden="true" className="size-3.5" />
                  Scroll to bottom
                </a>
              </Button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}
