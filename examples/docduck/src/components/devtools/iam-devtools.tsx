'use client'

/**
 * The duck-iam devtools, docked into docduck.
 *
 * docduck's engine is server-side - it holds a Drizzle adapter over Postgres -
 * and the devtools panels are client components that call `explain`,
 * `admin.listPolicies`, `admin.setAttributes` and friends directly. So the
 * browser gets its own engine, built on the same model definitions over
 * `IamHttpAdapter`, pointed at the `/api/iam` routes. Same policies, same
 * roles, same rows: one engine reads them through SQL, the other through
 * fetch.
 *
 * v2 rather than v1 because docduck is already a duck-ui app - the panel
 * inherits the Bun theme, the JetBrains Mono stack and the light/dark switch
 * from `globals.css` instead of shipping a palette of its own.
 */

import { IamHttpAdapter } from '@gentleduck/iam/adapters/http'
import {
  IamDevtoolsV2,
  type IamIDevtoolsMetrics,
  type IamIFlowRecorder,
  iamCreateFlowRecorder,
} from '@gentleduck/iam/dt/v2'
import { iamCreateMetricsAggregator } from '@gentleduck/iam/observability/metrics'
import React from 'react'
import { type AppAction, type AppResource, access } from '@/lib/access-model'

interface Wiring {
  engine: React.ComponentProps<typeof IamDevtoolsV2>['engine']
  flow: IamIFlowRecorder
  metrics: IamIDevtoolsMetrics
}

/**
 * Builds the browser-side engine. Called from an effect, never at module
 * scope: `baseUrl` needs `window.location.origin`, and the adapter validates
 * it in its constructor, so evaluating this during SSR would throw before the
 * page rendered.
 */
function createWiring(): Wiring {
  const flow = iamCreateFlowRecorder({ bufferSize: 300 })
  const metrics = iamCreateMetricsAggregator({ sampleSize: 500 })

  const adapter = new IamHttpAdapter<AppAction, AppResource, string, string>({
    // The panel talks to its own origin and nowhere else, which is what this
    // list says; `allowPrivateHosts` is the same statement for the loopback
    // address a local dev server may be served from, which the adapter
    // otherwise refuses. Both refusals are right for a deployment reaching out
    // to a policy server - here the policy server is this page.
    allowPrivateHosts: true,
    allowedHosts: [window.location.host],
    baseUrl: `${window.location.origin}/api/iam`,
    // Cookies are how the routes recognise the better-auth session; without
    // this every request arrives signed out and answers 401.
    fetch: (input, init) => fetch(input, { ...init, credentials: 'same-origin' }),
  })

  const engine = access.createEngine({
    adapter,
    hooks: {
      /**
       * One hook, not two. `afterEvaluate` is the only one that sees the
       * decision *and* its duration, so the Flow row it records carries the
       * deciding policy and rule rather than just a verdict.
       */
      afterEvaluate: (request, decision) => {
        flow.record({
          action: request.action,
          allowed: decision.allowed,
          decidingPolicy: decision.policy,
          decidingRule: decision.rule?.id,
          durationMs: decision.duration,
          environment: request.environment,
          reason: decision.reason,
          resource: request.resource.type,
          resourceId: request.resource.id,
          scope: request.scope,
          subjectId: request.subject?.id ?? '',
        })
      },
      onMetrics: (event) => metrics.record(event),
    },
    // Development mode is what makes `decision.policy` and `decision.rule`
    // exist at all - the compiled production table erases them - and it is
    // also the positive signal the devtools guard requires before it renders.
    mode: 'development',
  })

  return { engine, flow, metrics }
}

/**
 * Mounted from the root layout, and only outside production - see
 * `IAM_DEVTOOLS_ENABLED`. The panel carries duck-iam's own guard as well, but
 * the check that matters is the one on the routes.
 */
export function IamDevtools() {
  const [wiring, setWiring] = React.useState<Wiring | null>(null)

  React.useEffect(() => {
    setWiring(createWiring())
  }, [])

  if (!wiring) return null

  return (
    <IamDevtoolsV2
      defaultRequest={{
        action: 'read',
        attributesJson: '{ "ownerId": "", "isPublic": false }',
        resourceType: 'document',
      }}
      engine={wiring.engine}
      flow={wiring.flow}
      metrics={wiring.metrics}
      position="bottom"
    />
  )
}
